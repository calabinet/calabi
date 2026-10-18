// sni_ingress_test.go — an sni tunnel on a node with no TLS passthrough
// listener is refused, not registered into a table nothing reads.
//
// What used to happen with tunnel.sni_port 0 (every node's default): the route
// went in, the persister wrote the row and reported it enabled, and the client
// showed a live tunnel that no visitor could reach.
//
// RUN: go test ./apps/calabi-edge/internal/session/ -run TestSNIIngress -v
package session

import (
	"testing"

	proto "github.com/calabinet/calabi/pkg/protocol"
)

// sniOffRegistrar answers RegisterSNI the way the edge's router bridge does on
// a node whose sni listener is off.
type sniOffRegistrar struct{ *portRegistrar }

func (sniOffRegistrar) RegisterSNI(string, *Session, string) error { return ErrSNIIngressOff }

// openRecorder counts OnProxyOpened: on the platform that call is what writes
// the row and reports it enabled.
type openRecorder struct{ opened int }

func (r *openRecorder) OnProxyOpened(*Session, *Proxy) (int64, error) { r.opened++; return 1, nil }
func (r *openRecorder) OnProxyClosed(*Session, *Proxy, string)        {}

func TestSNIIngressOffRefusesTheTunnel(t *testing.T) {
	s, pipe := newTestSession(t)
	rec := &openRecorder{}
	resp := newProxy(t, s, pipe, sniOffRegistrar{newPortRegistrar()}, nil, rec, proto.NewProxyRequest{
		Name: "tls", Type: proto.ProxyKindSNI, LocalAddr: "127.0.0.1:8443", Domain: "app.example.com",
	})

	if resp.Error == nil {
		t.Fatalf("sni registered on a node with no TLS passthrough listener (proxy_id=%q)", resp.ProxyID)
	}
	// A code that says what is wrong. CodeProxyDuplicate — what any registrar
	// error used to become — sends the client looking for a name collision.
	if resp.Error.Code != proto.CodeTypeNotEnabled || resp.Error.MessageKey != "calabi.err.proxy.sni_not_enabled" {
		t.Fatalf("refusal = code %d key %q, want %d calabi.err.proxy.sni_not_enabled",
			resp.Error.Code, resp.Error.MessageKey, proto.CodeTypeNotEnabled)
	}
	if resp.ProxyID != "" {
		t.Fatalf("a refused proxy was given an id: %q", resp.ProxyID)
	}
	if rec.opened != 0 {
		t.Fatal("the persister ran for a refused sni proxy — a row was written and reported enabled")
	}
	if n := len(s.Proxies()); n != 0 {
		t.Fatalf("session holds %d proxies after the refusal, want 0", n)
	}
}

// The control: where the registrar takes it, sni registers and persists.
func TestSNIIngressOnRegisters(t *testing.T) {
	s, pipe := newTestSession(t)
	rec := &openRecorder{}
	resp := newProxy(t, s, pipe, newPortRegistrar(), nil, rec, proto.NewProxyRequest{
		Name: "tls", Type: proto.ProxyKindSNI, LocalAddr: "127.0.0.1:8443", Domain: "app.example.com",
	})
	if resp.Error != nil {
		t.Fatalf("sni refused where the listener is on: %+v", resp.Error)
	}
	if rec.opened != 1 {
		t.Fatalf("persister ran %d times, want 1", rec.opened)
	}
}
