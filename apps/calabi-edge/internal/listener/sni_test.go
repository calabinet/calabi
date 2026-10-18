package listener

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/calabi-edge/internal/accesslog"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/mesh"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/policy"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/router"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/session"
	proto "github.com/calabinet/calabi/pkg/protocol"
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

// Exercise the real IP gate, including port 443's ClientHello dispatch. A
// blocked session makes an accidental fallthrough fail immediately rather than
// requiring a running daemon. No access sink is how a BYOI edge without NATS
// runs: the operator must still be able to find the refusal in its normal log.
func TestTLSPolicyDenialIsLogged(t *testing.T) {
	const host = "tls.example.com"
	const visitorIP = "203.0.113.9"
	hello := captureClientHello(t, host)
	for _, path := range []string{"https443", "dedicated", "forward"} {
		for _, config := range []struct {
			name, policy string
			denied       bool
		}{
			{"allowlist_miss", `{"security":{"ip":{"allow":["192.0.2.0/24"]}}}`, true},
			{"denylist_match", `{"security":{"ip":{"deny":["203.0.113.0/24"]}}}`, true},
			{"allowed", `{"security":{"ip":{"allow":["203.0.113.0/24"]}}}`, false},
		} {
			for _, withSink := range []bool{false, true} {
				sinkName := "without_sink"
				if withSink {
					sinkName = "with_sink"
				}
				t.Run(path+"/"+config.name+"/"+sinkName, func(t *testing.T) {
					var logs bytes.Buffer
					logger := slog.New(slog.NewJSONHandler(&logs, nil))
					pol, err := policy.Parse(config.policy)
					if err != nil {
						t.Fatal(err)
					}
					sess := session.New(logger, nil, nil)
					sess.TenantID = "7"
					p := &session.Proxy{ID: "tls-proxy", Type: proto.ProxyKindSNI, Domain: host, TunnelID: 42}
					p.SetPolicy(pol)
					if !sess.RegisterProxy(p) {
						t.Fatal("register proxy")
					}
					sess.SetBlockReason("no upstream attached in test")
					r := router.New()
					if err := r.RegisterSNI(host, sess, sess.ID, p.ID); err != nil {
						t.Fatal(err)
					}
					var sink tlsDenialSink
					accesslog.SetSink(nil)
					if withSink {
						accesslog.SetSink(&sink)
					}
					t.Cleanup(func() { accesslog.SetSink(nil) })
					var obs tlsDenialObserver
					sni := NewSNI(logger, SNIOptions{Router: r, Observer: &obs})
					certCalls := 0
					https := NewHTTPS(logger, HTTPSOptions{Router: r, Passthrough: sni.ServePeeked})
					tlsCfg := &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
						certCalls++
						return nil, errors.New("edge must not terminate a TLS endpoint")
					}}
					client, server := net.Pipe()
					t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
					_ = client.SetDeadline(time.Now().Add(5 * time.Second))
					conn := &tlsVisitorConn{Conn: server, ip: visitorIP}
					if path == "forward" {
						conn.ip = "198.51.100.5"
					}
					done := make(chan struct{})
					go func() {
						defer close(done)
						switch path {
						case "https443":
							https.serve(conn, tlsCfg)
						case "dedicated":
							sni.handle(conn)
						case "forward":
							NewForward(logger, ForwardOptions{Router: r, Observer: &obs}).handle(conn)
						}
					}()
					if path == "forward" {
						// The forwarded visitor differs from the peer's socket IP.
						_ = mesh.WriteFrame(client, mesh.ForwardHeader{
							Kind: mesh.KindSNI, Host: host, VisitorIP: visitorIP, VisitorPort: 12345,
						}, hello)
					} else {
						_, _ = client.Write(hello)
					}
					response, readErr := io.ReadAll(client)
					if readErr != nil {
						t.Fatal(readErr)
					}
					<-done
					if len(response) != 0 || certCalls != 0 {
						t.Fatalf("edge terminated or wrote plaintext into TLS: response=%q cert calls=%d", response, certCalls)
					}
					var denied []map[string]any
					decoder := json.NewDecoder(&logs)
					for decoder.More() {
						var row map[string]any
						if err := decoder.Decode(&row); err != nil {
							t.Fatal(err)
						}
						if row["outcome"] == accesslog.DeniedIP {
							denied = append(denied, row)
						}
					}
					if !config.denied {
						wantOutcome := "open_upstream_failed"
						if path == "forward" {
							wantOutcome = "sni_" + wantOutcome
						}
						if len(denied) != 0 || obs.outcome != wantOutcome {
							t.Fatalf("allowed IP was reported as denied: logs=%v outcome=%s", denied, obs.outcome)
						}
						return
					}
					if len(denied) != 1 {
						t.Fatalf("want exactly one IP refusal in default INFO log, got %v", denied)
					}
					for key, want := range map[string]any{
						"level": "INFO", "visitor_ip": visitorIP, "domain": host,
						"proxy_type": "sni", "proxy_id": p.ID, "session_id": sess.ID,
						"org_id": float64(7), "tunnel_id": float64(42),
					} {
						if denied[0][key] != want {
							t.Errorf("log %s = %v, want %v", key, denied[0][key], want)
						}
					}
					wantOutcome := "ip_denied"
					if path == "forward" {
						wantOutcome = "sni_" + wantOutcome
					}
					if obs.outcome != wantOutcome {
						t.Errorf("outcome = %q, want %s", obs.outcome, wantOutcome)
					}
					if withSink && (sink.calls != 1 || sink.orgID != 7 || sink.tunnelID != 42 || sink.ip != visitorIP || sink.outcome != accesslog.DeniedIP) {
						t.Errorf("access sink = %+v", sink)
					}
				})
			}
		}
	}
}

type tlsVisitorConn struct {
	net.Conn
	ip string
}

func (c *tlsVisitorConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP(c.ip), Port: 12345}
}

type tlsDenialObserver struct{ outcome string }

func (o *tlsDenialObserver) OnVisitorRequest(_, outcome string)    { o.outcome = outcome }
func (*tlsDenialObserver) OnBytesTransferred(_, _ string, _ int64) {}

type tlsDenialSink struct {
	calls           int
	orgID, tunnelID int64
	ip, outcome     string
}

func (s *tlsDenialSink) NoteAccess(orgID, tunnelID int64, ip, outcome string, _ time.Time) {
	s.calls++
	s.orgID, s.tunnelID, s.ip, s.outcome = orgID, tunnelID, ip, outcome
}
