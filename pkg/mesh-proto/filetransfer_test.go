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
	for name, mutate := range map[string]func(*meshpb.FileTransferInfo){
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
