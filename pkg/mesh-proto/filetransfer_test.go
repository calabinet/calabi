package meshproto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/dynamicpb"
)

func TestFileTransferBinding(t *testing.T) {
	now := time.Now()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	node := NodeKey{1}
	info := &meshpb.FileTransferInfo{Version: 1, Port: 17401, Receiving: true, Certificate: der, ExpiresUnix: now.Add(FileTransferLease).Unix()}
	if err := SignFileTransfer(node, info, key); err != nil {
		t.Fatal(err)
	}
	if pin, err := VerifyFileTransfer(node, info, now); err != nil || len(pin) != 64 {
		t.Fatalf("pin=%s err=%v", pin, err)
	}
	if err := SignDesktopCapabilities(node, info, key, true); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFileTransfer(node, info, now); err != nil {
		t.Fatal(err)
	}
	// The deployed v1 coordinator clones the declaration in memory. Exercise its
	// old six-field schema so an upgrade cannot silently require a new coordinator.
	t.Run("legacy coordinator forwards optional proof", func(t *testing.T) {
		fd := protodesc.ToFileDescriptorProto(meshpb.File_meshpb_coord_proto)
		for _, m := range fd.MessageType {
			if m.GetName() == "FileTransferInfo" {
				m.Field = m.Field[:6]
			}
		}
		legacy, err := protodesc.NewFile(fd, nil)
		if err != nil {
			t.Fatal(err)
		}
		old := dynamicpb.NewMessage(legacy.Messages().ByName("FileTransferInfo"))
		wire, err := proto.Marshal(info)
		if err != nil {
			t.Fatal(err)
		}
		if err := proto.Unmarshal(wire, old); err != nil {
			t.Fatal(err)
		}
		wire, err = proto.Marshal(proto.Clone(old))
		if err != nil {
			t.Fatal(err)
		}
		var forwarded meshpb.FileTransferInfo
		if err := proto.Unmarshal(wire, &forwarded); err != nil || !proto.Equal(info, &forwarded) {
			t.Fatal("capability lost during v1 relay", err)
		}
	})
	for name, mutate := range map[string]func(*meshpb.FileTransferInfo){
		"assistance":  func(i *meshpb.FileTransferInfo) { i.AssistanceProof = append([]byte(nil), i.Proof...) },
		"port":        func(i *meshpb.FileTransferInfo) { i.Port++ },
		"receiving":   func(i *meshpb.FileTransferInfo) { i.Receiving = false },
		"expiry":      func(i *meshpb.FileTransferInfo) { i.ExpiresUnix++ },
		"version":     func(i *meshpb.FileTransferInfo) { i.Version++ },
		"certificate": func(i *meshpb.FileTransferInfo) { i.Certificate[0] ^= 1 },
		"signature":   func(i *meshpb.FileTransferInfo) { i.Proof[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := proto.Clone(info).(*meshpb.FileTransferInfo)
			mutate(changed)
			if _, err := VerifyFileTransfer(node, changed, now); err == nil {
				t.Fatal("tampering accepted")
			}
		})
	}
	if _, err := VerifyFileTransfer(NodeKey{2}, info, now); err == nil {
		t.Fatal("another node's proof accepted")
	}
	if _, err := VerifyFileTransfer(node, info, now.Add(FileTransferLease)); err == nil {
		t.Fatal("expired lease accepted")
	}
	info.ExpiresUnix = now.Add(10 * time.Minute).Unix()
	if err := SignFileTransfer(node, info, key); err == nil {
		t.Fatal("unbounded lease accepted")
	}
}
