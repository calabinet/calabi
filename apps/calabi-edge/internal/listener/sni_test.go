package listener

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// TestPeekSNI_GoldenClientHello exercises the parser against a real
// ClientHello produced by crypto/tls. We grab the bytes off the wire
// (via a pipe) and parse them; the parser must recover the original SNI.
func TestPeekSNI_GoldenClientHello(t *testing.T) {
	hello := captureClientHello(t, "tunnels.example.com")

	br := bufio.NewReader(bytes.NewReader(hello))
	head, host, err := peekSNI(br)
	if err != nil {
		t.Fatalf("peekSNI: %v", err)
	}
	if host != "tunnels.example.com" {
		t.Fatalf("want sni=tunnels.example.com got %q", host)
	}
	if !bytes.Equal(head, hello[:len(head)]) {
		t.Fatalf("returned head does not match wire bytes verbatim")
	}
	// peekSNI consumes the bytes it returned in `head` so the caller
	// can io.Copy the remainder without double-shipping the ClientHello.
	// The rest of the stream (post-ClientHello bytes from the handshake
	// loop, if any) should be available.
	rest, _ := io.ReadAll(br)
	if bytes.HasPrefix(rest, head) {
		t.Fatalf("br still contains the head bytes; Discard must consume them")
	}
	if len(rest)+len(head) != len(hello) {
		t.Fatalf("bytes accounting: head=%d rest=%d total=%d, want %d",
			len(head), len(rest), len(head)+len(rest), len(hello))
	}
}

// TestPeekSNI_CaseInsensitive verifies the SNI value is lower-cased so
// the router lookup is consistent regardless of how the client encoded
// it (some clients send mixed case).
func TestPeekSNI_CaseInsensitive(t *testing.T) {
	hello := captureClientHello(t, "MIXED.Example.COM")
	_, host, err := peekSNI(bufio.NewReader(bytes.NewReader(hello)))
	if err != nil {
		t.Fatalf("peekSNI: %v", err)
	}
	if host != "mixed.example.com" {
		t.Fatalf("want lower-cased mixed.example.com, got %q", host)
	}
}

// TestPeekSNI_NotTLS rejects a non-TLS connection (e.g. a port-scanner
// sending a single byte).
func TestPeekSNI_NotTLS(t *testing.T) {
	br := bufio.NewReader(bytes.NewReader([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}))
	_, _, err := peekSNI(br)
	if err == nil {
		t.Fatalf("expected error on non-TLS bytes")
	}
	if !strings.Contains(err.Error(), "TLS handshake") {
		t.Fatalf("error should call out wrong record type, got %q", err)
	}
}

// TestPeekSNI_TruncatedRecord ensures we error rather than block forever
// when the visitor sends a partial record (the bufio.Reader is
// unbacked-by-network here but the failure mode must be the same).
func TestPeekSNI_TruncatedRecord(t *testing.T) {
	// 22 = handshake; legal record length but no body.
	truncated := []byte{0x16, 0x03, 0x01, 0x00, 0xff /* claims 255 bytes but we deliver 0 */}
	br := bufio.NewReader(bytes.NewReader(truncated))
	_, _, err := peekSNI(br)
	if err == nil {
		t.Fatalf("expected error on truncated record")
	}
}

// captureClientHello returns the raw ClientHello bytes produced by
// crypto/tls.Client when handshaking against a stub server. We tee the
// bytes off the connection rather than parse them via crypto/tls so the
// test exercises our hand-written parser end-to-end against the stdlib's
// wire format.
func captureClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	// Build a self-signed cert just so tls.Server has something to
	// answer with. The handshake will fail (we don't complete it) but
	// the ClientHello bytes have been written before that.
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "stub"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}

	// Pipe: tls.Client writes -> tee captures -> tls.Server reads.
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	var captured bytes.Buffer
	teed := &teeConn{Conn: serverConn, sink: &captured}

	done := make(chan struct{})
	go func() {
		defer close(done)
		// The server-side handshake will fail because we provide a cert
		// that doesn't match anything the client trusts. That's fine —
		// we only need the ClientHello bytes to be written by the
		// client first, which they are.
		_ = tls.Server(teed, &tls.Config{Certificates: []tls.Certificate{cert}}).Handshake()
	}()
	c := tls.Client(clientConn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, // we don't care; we abort after ClientHello
	})
	// Give the handshake a chance to send the ClientHello; it'll error
	// out shortly after.
	_ = c.Handshake()
	<-done

	if captured.Len() == 0 {
		t.Fatalf("no bytes captured from handshake")
	}
	return captured.Bytes()
}

// teeConn duplicates everything read from the underlying conn into sink.
type teeConn struct {
	net.Conn
	sink io.Writer
}

func (t *teeConn) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	if n > 0 {
		_, _ = t.sink.Write(p[:n])
	}
	return n, err
}

// helper to satisfy go vet about unused imports if the tls handshake
// goes too fast and we never bind. errors.Is for ErrClosedPipe.
var _ = errors.Is
