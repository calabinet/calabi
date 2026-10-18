// https_passthrough_test.go — TLS passthrough on the HTTPS port.
// On a node that serves one
// organization, the HTTPS listener reads the ClientHello's server_name before
// any handshake: a name in the SNI table is handed on untouched, every other
// connection is terminated exactly as before.
//
// Two parties can answer a ClientHello here, each with its own CA: the edge
// (the certificate GetCertificate returns) and the user's service (one the
// edge never sees). A client that trusts only one of them can only finish a
// handshake with that one — which is how these tests tell "passed through"
// from "terminated" without looking inside the listener.
//
// RUN: go test ./apps/calabi-edge/internal/listener/ -run TestHTTPSPassthrough -v
package listener

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/calabi-edge/internal/router"
)

const (
	ownName = "own.example.com" // the TLS (passthrough) endpoint
	webName = "web.example.com" // an ordinary HTTPS endpoint on the same node
)

// testCert issues a leaf for names under a fresh CA and returns the pool that
// trusts it.
func testCert(t *testing.T, names ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test ca " + names[0]},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}, pool
}

// userService plays what sits behind a passthrough endpoint: the client
// replays the bytes it is handed to the user's own TLS server.
type userService struct {
	cert tls.Certificate

	mu    sync.Mutex
	hosts []string
	heads [][]byte
}

func (u *userService) serve(visitor net.Conn, br *bufio.Reader, head []byte, host string) {
	defer visitor.Close()
	u.mu.Lock()
	u.hosts = append(u.hosts, host)
	u.heads = append(u.heads, append([]byte(nil), head...))
	u.mu.Unlock()
	conn := &replayConn{Conn: visitor, r: io.MultiReader(bytes.NewReader(head), br)}
	srv := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{u.cert}})
	_ = srv.SetDeadline(time.Now().Add(5 * time.Second))
	if err := srv.Handshake(); err != nil {
		return
	}
	_, _ = io.WriteString(srv, "from the user's service\n")
	_ = srv.Close()
}

func (u *userService) calls() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.hosts...)
}

type replayConn struct {
	net.Conn
	r io.Reader
}

func (c *replayConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// edgeCerts is the edge's own certificate source, recording the server names
// it was asked for (a call at all means the edge terminated).
type edgeCerts struct {
	cert tls.Certificate

	mu    sync.Mutex
	asked []string
}

func (e *edgeCerts) get(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	e.mu.Lock()
	e.asked = append(e.asked, hi.ServerName)
	e.mu.Unlock()
	return &e.cert, nil
}

func (e *edgeCerts) calls() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.asked...)
}

// startHTTPS serves an HTTPS listener on loopback and returns its address.
// pass == nil is a node without passthrough (a platform node).
func startHTTPS(t *testing.T, r *router.Router, certs *edgeCerts, pass *userService) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	opts := HTTPSOptions{Router: r, GetCertificate: certs.get}
	if pass != nil {
		opts.Passthrough = pass.serve
	}
	h := NewHTTPS(discardLogger(), opts)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = h.serveListener(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return ln.Addr().String()
}

// slowHello delays the bulk of the client's first write — its ClientHello —
// by pause, after sending the first few bytes.
type slowHello struct {
	net.Conn
	pause time.Duration
	once  sync.Once
}

func (s *slowHello) Write(p []byte) (int, error) {
	first := false
	s.once.Do(func() { first = true })
	if !first || len(p) < 4 {
		return s.Conn.Write(p)
	}
	n, err := s.Conn.Write(p[:3])
	if err != nil {
		return n, err
	}
	time.Sleep(s.pause)
	m, err := s.Conn.Write(p[3:])
	return n + m, err
}

// dial handshakes with addr as serverName ("" sends no SNI), trusting roots
// (nil trusts anything). helloPause > 0 sends the ClientHello slowly.
func dial(t *testing.T, addr, serverName string, roots *x509.CertPool, helloPause time.Duration) (*tls.Conn, error) {
	t.Helper()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	var c net.Conn = raw
	if helloPause > 0 {
		c = &slowHello{Conn: raw, pause: helloPause}
	}
	cfg := &tls.Config{ServerName: serverName, RootCAs: roots, MinVersion: tls.VersionTLS12}
	if roots == nil {
		cfg.InsecureSkipVerify = true
	}
	tc := tls.Client(c, cfg)
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	return tc, tc.Handshake()
}

func readAll(t *testing.T, c net.Conn) string {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, _ := io.ReadAll(c)
	return string(b)
}

// setup builds a node with one passthrough endpoint (ownName) and the two
// certificate holders.
func setup(t *testing.T) (*router.Router, *edgeCerts, *x509.CertPool, *userService, *x509.CertPool) {
	t.Helper()
	r := router.New()
	if err := r.RegisterSNI(ownName, nil, "s1", "p-own"); err != nil {
		t.Fatal(err)
	}
	// The edge's certificate covers BOTH names, so a client that trusts the
	// edge would accept it for ownName too — terminating a passthrough name is
	// then visible as a handshake that succeeds with the wrong party.
	edgeCert, edgePool := testCert(t, webName, ownName)
	userCert, userPool := testCert(t, ownName)
	return r, &edgeCerts{cert: edgeCert}, edgePool, &userService{cert: userCert}, userPool
}

// The passthrough name reaches the user's service with its ClientHello intact,
// and the handshake completes against a certificate the edge never had.
func TestHTTPSPassthrough_TLSEndpointIsPassedThrough(t *testing.T) {
	r, certs, _, user, userPool := setup(t)
	addr := startHTTPS(t, r, certs, user)

	c, err := dial(t, addr, ownName, userPool, 0)
	if err != nil {
		t.Fatalf("handshake with the user's service failed (did the edge terminate it?): %v", err)
	}
	if got := readAll(t, c); got != "from the user's service\n" {
		t.Fatalf("read %q from the passthrough endpoint", got)
	}
	if got := user.calls(); len(got) != 1 || got[0] != ownName {
		t.Fatalf("passthrough calls = %v, want [%s]", got, ownName)
	}
	if head := user.heads[0]; len(head) < 6 || head[0] != 22 || head[5] != 1 {
		t.Fatalf("passthrough head is not a ClientHello record: % x", head[:min(len(head), 8)])
	}
	if got := certs.calls(); len(got) != 0 {
		t.Fatalf("the edge was asked for a certificate (%v): it terminated a passthrough name", got)
	}
}

// Every other name on the node is terminated by the edge, as it always was.
func TestHTTPSPassthrough_OtherNamesAreTerminated(t *testing.T) {
	r, certs, edgePool, user, _ := setup(t)
	addr := startHTTPS(t, r, certs, user)

	c, err := dial(t, addr, webName, edgePool, 0)
	if err != nil {
		t.Fatalf("handshake with the edge failed: %v", err)
	}
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: "+webName+"\r\n\r\n")
	// No http route for webName: the edge answers with its own error page —
	// which it can only do having terminated the TLS.
	if got := readAll(t, c); !strings.Contains(got, "502") {
		t.Fatalf("want the edge's 502 for an unrouted name; got %q", got)
	}
	if got := certs.calls(); len(got) != 1 || got[0] != webName {
		t.Fatalf("edge certificate requests = %v, want [%s]", got, webName)
	}
	if got := user.calls(); len(got) != 0 {
		t.Fatalf("an ordinary HTTPS name was passed through: %v", got)
	}
}

// A ClientHello without server_name cannot be a passthrough name; it is
// terminated rather than dropped.
func TestHTTPSPassthrough_NoSNIIsTerminated(t *testing.T) {
	r, certs, _, user, _ := setup(t)
	addr := startHTTPS(t, r, certs, user)

	if _, err := dial(t, addr, "", nil, 0); err != nil {
		t.Fatalf("a hello without SNI was not terminated: %v", err)
	}
	if got := certs.calls(); len(got) != 1 || got[0] != "" {
		t.Fatalf("edge certificate requests = %q, want one with no server name", got)
	}
	if got := user.calls(); len(got) != 0 {
		t.Fatalf("a hello without SNI was passed through: %v", got)
	}
}

// A ClientHello that arrives slowly still reaches the passthrough endpoint.
// The dedicated sni_port listener gives up after 200ms; port 443 serves
// every visitor of the node and must not.
func TestHTTPSPassthrough_SlowHelloStillPassedThrough(t *testing.T) {
	r, certs, _, user, userPool := setup(t)
	addr := startHTTPS(t, r, certs, user)

	c, err := dial(t, addr, ownName, userPool, 600*time.Millisecond)
	if err != nil {
		t.Fatalf("slow hello: handshake with the user's service failed: %v", err)
	}
	if got := readAll(t, c); got != "from the user's service\n" {
		t.Fatalf("slow hello: read %q", got)
	}
}

// The same for a slow hello to an ordinary name: terminated, not dropped.
func TestHTTPSPassthrough_SlowHelloStillTerminated(t *testing.T) {
	r, certs, edgePool, user, _ := setup(t)
	addr := startHTTPS(t, r, certs, user)

	if _, err := dial(t, addr, webName, edgePool, 600*time.Millisecond); err != nil {
		t.Fatalf("slow hello to an ordinary name: %v", err)
	}
}

// A node without passthrough (a platform node) terminates every name, even
// one that has an SNI route — port 443 there is never handed to anyone.
func TestHTTPSPassthrough_OffTerminatesEverything(t *testing.T) {
	r, certs, edgePool, _, _ := setup(t)
	addr := startHTTPS(t, r, certs, nil)

	if _, err := dial(t, addr, ownName, edgePool, 0); err != nil {
		t.Fatalf("passthrough off: the edge did not terminate %s: %v", ownName, err)
	}
	if got := certs.calls(); len(got) != 1 || got[0] != ownName {
		t.Fatalf("edge certificate requests = %v, want [%s]", got, ownName)
	}
}
