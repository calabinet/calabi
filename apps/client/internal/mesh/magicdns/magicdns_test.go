package magicdns

import (
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

type fakeRW struct{ msg *dns.Msg }

func (f *fakeRW) WriteMsg(m *dns.Msg) error   { f.msg = m; return nil }
func (f *fakeRW) Write(b []byte) (int, error) { return len(b), nil }
func (f *fakeRW) Close() error                { return nil }
func (f *fakeRW) TsigStatus() error           { return nil }
func (f *fakeRW) TsigTimersOnly(bool)         {}
func (f *fakeRW) Hijack()                     {}
func (f *fakeRW) LocalAddr() net.Addr         { return &net.UDPAddr{} }
func (f *fakeRW) RemoteAddr() net.Addr        { return &net.UDPAddr{} }

func testResolver() *Resolver {
	r := New("meshnet-1.mesh", "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.SetRecords(map[string]netip.Addr{
		"node-b": netip.MustParseAddr("100.64.0.2"),
		"node-a": netip.MustParseAddr("100.64.0.1"),
	})
	return r
}

func query(r *Resolver, name string, qtype uint16) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(name, qtype)
	fw := &fakeRW{}
	r.ServeDNS(fw, req)
	return fw.msg
}

func TestResolverShortAndFQDN(t *testing.T) {
	r := testResolver()
	for _, name := range []string{"node-b.", "NODE-B.", "node-b.meshnet-1.mesh."} {
		m := query(r, name, dns.TypeA)
		if m == nil || len(m.Answer) != 1 {
			t.Fatalf("%s: expected 1 answer, got %v", name, m)
		}
		a, ok := m.Answer[0].(*dns.A)
		if !ok || a.A.String() != "100.64.0.2" {
			t.Fatalf("%s: A = %v", name, m.Answer[0])
		}
		if !m.Authoritative {
			t.Fatalf("%s: answer should be authoritative", name)
		}
	}
}

func TestResolverKnownNameAAAAEmpty(t *testing.T) {
	// A mesh name queried for AAAA: NOERROR, no records, never forwarded.
	m := query(testResolver(), "node-b.", dns.TypeAAAA)
	if m == nil || m.Rcode != dns.RcodeSuccess || len(m.Answer) != 0 {
		t.Fatalf("AAAA on mesh name should be empty NOERROR, got %v", m)
	}
}

func TestResolverUnknownRefusedWithoutUpstream(t *testing.T) {
	m := query(testResolver(), "example.com.", dns.TypeA)
	if m == nil || m.Rcode != dns.RcodeRefused {
		t.Fatalf("unknown name w/o upstream should be REFUSED, got %v", m)
	}
}

func TestResolverLiveUpdate(t *testing.T) {
	r := testResolver()
	// node-c not present yet.
	if m := query(r, "node-c.", dns.TypeA); m.Rcode != dns.RcodeRefused {
		t.Fatalf("node-c should be unknown initially")
	}
	r.SetRecords(map[string]netip.Addr{"node-c": netip.MustParseAddr("100.64.0.3")})
	if m := query(r, "node-c.", dns.TypeA); len(m.Answer) != 1 {
		t.Fatalf("node-c should resolve after SetRecords")
	}
	// node-b gone after the swap.
	if m := query(r, "node-b.", dns.TypeA); m.Rcode != dns.RcodeRefused {
		t.Fatalf("node-b should be gone after record swap")
	}
}
