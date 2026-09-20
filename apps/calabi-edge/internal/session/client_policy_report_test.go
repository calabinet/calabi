// client_policy_report_test.go — the edge must SAY what it did with the
// policy the client offered.
//
// Whether a client-supplied policy is honoured is the edge's decision:
// standalone mode AND no control plane wired (config.TrustsClientPolicy). The
// client knows only what IT declared — `--standalone`, or `calabi mode
// standalone` — and that declaration is not an observation.
//
// It was being treated as one. The CLI printed "these flags only take effect on
// a self-hosted edge" and suppressed that note whenever the client had declared
// standalone. A BYOI edge is standalone in spirit and control-plane-wired in
// fact, so it does NOT apply client policy — and the note was already silenced.
// `--basic-auth` then went nowhere: the edge did not apply it, tunnel-svc keeps
// only the IP rules (store.MergeClientProposedIP), and nothing anywhere said so.
// The tunnel row is empty, both consoles correctly show no security, and the
// user believes the tunnel has a password.
//
// So the answer goes on the wire, from the only party that knows it.
//
// RUN: go test./apps/calabi-edge/internal/session/ -run TestClientPolicyReport -v
package session

import (
	"testing"

	proto "github.com/calabinet/calabi/pkg/protocol"
)

const clientPolicyBlob = `{"security":{"basic_auth":{"users":[{"user":"u","hash":"$2a$10$abcdefghijklmnopqrstuv"}]},` +
	`"ip":{"allow":["203.0.113.0/24"]}}}`

func newProxyWithPolicy(t *testing.T, trust bool, blob string) (proto.NewProxyResponse, *Session) {
	t.Helper()
	s, pipe := newTestSession(t)
	s.TrustClientPolicy = trust
	req := proto.NewProxyRequest{
		Name: "web", Type: proto.ProxyKindHTTP, LocalAddr: "127.0.0.1:8080",
	}
	if blob != "" {
		req.Options = &proto.ProxyOptions{SecurityConfigJSON: blob}
	}
	resp := newProxy(t, s, pipe, newPortRegistrar(), newTestPool(), newPortLedger(), req)
	if resp.Error != nil {
		t.Fatalf("NEW_PROXY refused: %+v", resp.Error)
	}
	return resp, s
}

// A control-plane-wired edge (managed OR BYOI) does not apply client policy.
// It has to say so, because this is the case the client cannot detect.
func TestClientPolicyReportRelayedWhenNotTrusted(t *testing.T) {
	resp, s := newProxyWithPolicy(t, false, clientPolicyBlob)

	if resp.ClientPolicy != proto.ClientPolicyRelayed {
		t.Fatalf("client_policy = %q, want %q — a client that is not told this "+
			"has to guess, and the guess is what silently dropped --basic-auth",
			resp.ClientPolicy, proto.ClientPolicyRelayed)
	}
	// And it really did not apply it: the answer must describe what happened.
	for _, p := range s.Proxies() {
		if pol := p.LoadPolicy(); pol != nil {
			t.Fatal("the edge reported \"relayed\" but applied the policy anyway")
		}
	}
}

// A genuinely standalone edge applies it — and says so, so the CLI stays quiet
// instead of warning about something that did happen.
func TestClientPolicyReportAppliedWhenTrusted(t *testing.T) {
	resp, s := newProxyWithPolicy(t, true, clientPolicyBlob)

	if resp.ClientPolicy != proto.ClientPolicyApplied {
		t.Fatalf("client_policy = %q, want %q", resp.ClientPolicy, proto.ClientPolicyApplied)
	}
	applied := false
	for _, p := range s.Proxies() {
		if pol := p.LoadPolicy(); pol != nil && pol.HasBasicAuth() {
			applied = true
		}
	}
	if !applied {
		t.Fatal("reported \"applied\" but no policy is on the proxy")
	}
}

// No policy offered, nothing to report. An answer here would make every plain
// `calabi http 8080` carry a field about a thing that never happened — and the
// CLI keys its note off this field being set.
func TestClientPolicyReportSilentWhenNonePassed(t *testing.T) {
	for _, trust := range []bool{false, true} {
		resp, _ := newProxyWithPolicy(t, trust, "")
		if resp.ClientPolicy != "" {
			t.Fatalf("trust=%v: client_policy = %q, want empty", trust, resp.ClientPolicy)
		}
	}
}
