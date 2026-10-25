package meshproto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"

	"github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
)

// FileTransferLease is deliberately short. A stopped user agent must not remain
// advertised by its machine daemon, even if its last withdrawal was lost.
const FileTransferLease = 90 * time.Second

func fileTransferMessage(node NodeKey, info *meshpb.FileTransferInfo) []byte {
	b := append([]byte("calabi/file-transfer/v1\x00"), node[:]...)
	b = binary.BigEndian.AppendUint32(b, info.Version)
	b = binary.BigEndian.AppendUint32(b, info.Port)
	if info.Receiving {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	b = binary.BigEndian.AppendUint64(b, uint64(info.ExpiresUnix))
	h := sha256.Sum256(info.Certificate)
	return append(b, h[:]...)
}

// SignFileTransfer uses only the separate TLS key, never a WireGuard key.
func SignFileTransfer(node NodeKey, info *meshpb.FileTransferInfo, key ed25519.PrivateKey) error {
	if info == nil || node.IsZero() || len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid file identity")
	}
	info.Proof = ed25519.Sign(key, fileTransferMessage(node, info))
	_, err := VerifyFileTransfer(node, info, time.Now())
	return err
}

// VerifyFileTransfer checks key possession and binding, as well as the short
// authorization lifetime. The certificate is pinned via the authenticated
// netmap, not trusted as a general-purpose CA or as a claim about a person.
func VerifyFileTransfer(node NodeKey, info *meshpb.FileTransferInfo, now time.Time) (string, error) {
	if node.IsZero() || info == nil || info.Version != 1 || info.Port < 1024 || info.Port > 65535 || len(info.Certificate) > 4096 || len(info.Proof) != ed25519.SignatureSize {
		return "", errors.New("invalid file transfer declaration")
	}
	expires := time.Unix(info.ExpiresUnix, 0)
	if !now.Before(expires) || expires.After(now.Add(FileTransferLease+5*time.Second)) {
		return "", errors.New("invalid file transfer lease")
	}
	cert, err := x509.ParseCertificate(info.Certificate)
	if err != nil {
		return "", errors.New("invalid file transfer certificate")
	}
	key, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || now.Before(cert.NotBefore) || expires.After(cert.NotAfter) || cert.IsCA || cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return "", errors.New("invalid file transfer certificate usage or lifetime")
	}
	client, server := false, false
	for _, usage := range cert.ExtKeyUsage {
		client = client || usage == x509.ExtKeyUsageClientAuth
		server = server || usage == x509.ExtKeyUsageServerAuth
	}
	if !client || !server || !ed25519.Verify(key, fileTransferMessage(node, info), info.Proof) {
		return "", errors.New("invalid file transfer possession proof")
	}
	h := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(h[:]), nil
}
