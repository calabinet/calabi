package router

import (
	"testing"
)

// TestRouter_SNIRoundTrip exercises register/lookup/unregister for SNI,
// which lives in its own table independent from HTTP. (One name cannot be in
// both tables — TestRouter_HTTPAndSNIExcludeEachOther.)
func TestRouter_SNIRoundTrip(t *testing.T) {
	r := New()
	if err := r.RegisterSNI("FOO.example.com", "sess-A", "s1", "p1"); err != nil {
		t.Fatalf("register sni: %v", err)
	}
	target, ok := r.LookupSNI("foo.example.com") // case-insensitive
	if !ok || target.ProxyID != "p1" {
		t.Fatalf("lookup sni: ok=%v target=%+v", ok, target)
	}
	// HTTP-table lookup on the same domain must miss (separate tables).
	if _, ok := r.LookupHTTP("foo.example.com"); ok {
		t.Fatalf("sni domain should not appear in http table")
	}
	// Duplicate SNI registration fails.
	if err := r.RegisterSNI("foo.example.com", "sess-B", "s2", "p2"); err == nil {
		t.Fatalf("duplicate sni domain should fail")
	}
	r.UnregisterByProxyID("p1")
	if _, ok := r.LookupSNI("foo.example.com"); ok {
		t.Fatalf("sni route survived unregister")
	}
}

// TestRouter_HTTPAndSNIExcludeEachOther: port 443 serves both tables — a name
// in the SNI table is passed through, any other name is terminated — so one
// name in both would make which one a visitor reaches depend on the listener's
// order of lookups. Whichever registered first keeps the name; the other is
// refused, and the refusal does not disturb the holder. The control plane
// already keeps a domain on one tunnel; a standalone node has no control plane,
// so this is the only place that holds there.
func TestRouter_HTTPAndSNIExcludeEachOther(t *testing.T) {
	r := New()
	if err := r.RegisterHTTP("web.example.com", "sess-A", "s1", "p-http"); err != nil {
		t.Fatalf("register http: %v", err)
	}
	if err := r.RegisterSNI("WEB.example.com", "sess-B", "s2", "p-sni"); err == nil {
		t.Fatal("sni on a name the http table holds should fail")
	}
	if _, ok := r.LookupSNI("web.example.com"); ok {
		t.Fatal("the refused sni route was filed anyway")
	}
	if tgt, ok := r.LookupHTTP("web.example.com"); !ok || tgt.ProxyID != "p-http" {
		t.Fatalf("http holder disturbed: ok=%v target=%+v", ok, tgt)
	}

	if err := r.RegisterSNI("own.example.com", "sess-B", "s2", "p-sni2"); err != nil {
		t.Fatalf("register sni: %v", err)
	}
	if err := r.RegisterHTTP("own.example.com", "sess-A", "s1", "p-http2"); err == nil {
		t.Fatal("http on a name the sni table holds should fail")
	}
	if _, ok := r.LookupHTTP("own.example.com"); ok {
		t.Fatal("the refused http route was filed anyway")
	}

	// Once the holder goes, the name is free for the other kind.
	r.UnregisterByProxyID("p-sni2")
	if err := r.RegisterHTTP("own.example.com", "sess-A", "s1", "p-http3"); err != nil {
		t.Fatalf("http after the sni holder left: %v", err)
	}
}

// TestRouter_HasSNIRoutes: the HTTPS listener asks this before reading a
// ClientHello itself, so a node with no passthrough route terminates exactly as
// it always did.
func TestRouter_HasSNIRoutes(t *testing.T) {
	r := New()
	if r.HasSNIRoutes() {
		t.Fatal("empty router reports sni routes")
	}
	_ = r.RegisterHTTP("web.example.com", nil, "s", "p-http")
	if r.HasSNIRoutes() {
		t.Fatal("an http route counted as an sni route")
	}
	_ = r.RegisterSNI("own.example.com", nil, "s", "p-sni")
	if !r.HasSNIRoutes() {
		t.Fatal("sni route not reported")
	}
	r.UnregisterByProxyID("p-sni")
	if r.HasSNIRoutes() {
		t.Fatal("sni route still reported after unregister")
	}
}

// TestRouter_UDPRoundTrip exercises register/lookup/unregister for UDP.
// The udp table is independent from tcp — same port number is allowed
// in both because TCP/UDP/<port> are distinct OS resources.
func TestRouter_UDPRoundTrip(t *testing.T) {
	r := New()
	if err := r.RegisterUDP(20001, "sess-A", "s1", "p1"); err != nil {
		t.Fatalf("register udp: %v", err)
	}
	target, ok := r.LookupUDP(20001)
	if !ok || target.ProxyID != "p1" {
		t.Fatalf("lookup udp: ok=%v target=%+v", ok, target)
	}
	// Same port on TCP must coexist.
	if err := r.RegisterTCP(20001, "sess-A", "s1", "p2"); err != nil {
		t.Fatalf("tcp on same port must coexist with udp: %v", err)
	}
	if _, ok := r.LookupTCP(20001); !ok {
		t.Fatalf("tcp lookup missed after coexistent register")
	}
	r.UnregisterByProxyID("p1")
	if _, ok := r.LookupUDP(20001); ok {
		t.Fatalf("udp route survived unregister")
	}
	// TCP entry must survive the unrelated UDP unregister.
	if _, ok := r.LookupTCP(20001); !ok {
		t.Fatalf("tcp route nuked by unrelated udp unregister")
	}
}

// TestRouter_Snapshot returns all four tables.
func TestRouter_Snapshot(t *testing.T) {
	r := New()
	_ = r.RegisterHTTP("h.example.com", nil, "s", "p-http")
	_ = r.RegisterSNI("s.example.com", nil, "s", "p-sni")
	_ = r.RegisterTCP(20001, nil, "s", "p-tcp")
	_ = r.RegisterUDP(20002, nil, "s", "p-udp")

	httpD, sniD, tcpP, udpP := r.Snapshot()
	if len(httpD) != 1 || len(sniD) != 1 || len(tcpP) != 1 || len(udpP) != 1 {
		t.Fatalf("snapshot counts: http=%d sni=%d tcp=%d udp=%d",
			len(httpD), len(sniD), len(tcpP), len(udpP))
	}
}

// TestRouter_RejectsEmptySNI mirrors the HTTP behavior (empty domain
// is invalid; nobody can route on "").
func TestRouter_RejectsEmptySNI(t *testing.T) {
	r := New()
	if err := r.RegisterSNI("   ", nil, "s", "p"); err == nil {
		t.Fatalf("empty sni domain should fail")
	}
}

// fakeConnCloser stands in for *session.Session at the router boundary.
type fakeConnCloser struct{ closed []string }

func (f *fakeConnCloser) CloseProxyConns(proxyID string) int {
	f.closed = append(f.closed, proxyID)
	return 0
}

// removing a route must also drop the in-flight visitor connections
// riding that proxy (so disable / CLOSE_PROXY stops existing keep-alive
// connections, not just new lookups). UnregisterByProxyID calls back into
// the owning session via the connCloser interface.
func TestRouter_UnregisterClosesInflightConns(t *testing.T) {
	r := New()
	sess := &fakeConnCloser{}
	if err := r.RegisterHTTP("h.example.com", sess, "s1", "p1"); err != nil {
		t.Fatalf("register: %v", err)
	}
	r.UnregisterByProxyID("p1")
	if len(sess.closed) != 1 || sess.closed[0] != "p1" {
		t.Fatalf("expected CloseProxyConns(p1) call, got %v", sess.closed)
	}
	// A session that doesn't implement connCloser (or nil) must not panic.
	if err := r.RegisterTCP(21000, "plain-string-sess", "s2", "p2"); err != nil {
		t.Fatalf("register tcp: %v", err)
	}
	r.UnregisterByProxyID("p2") // must be a no-op close, no panic
}
