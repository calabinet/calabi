package session

import (
	"testing"
	"time"

	proto "github.com/calabinet/calabi/pkg/protocol"
)

// testTokens is a TokenVerifier as calabi.net's edges wire it (bff-edge checks
// the account's token): one token, one tenant.
type testTokens struct{ token string }

func (v testTokens) Verify(token string) (tenantID, workspaceID, clientID string, ok bool) {
	if token != v.token {
		return "", "", "", false
	}
	return "42", "default", "client-9", true
}

// tokenHandshake runs the edge's side with the token verifier — calabi.net's
// route through the same handshake — and the client's side sending auth.
func (r edgeRig) tokenHandshake(t *testing.T, v TokenVerifier, auth proto.AuthRequest) (HandshakeResult, error, proto.HelloAck, proto.AuthResponse) {
	t.Helper()
	type result struct {
		res HandshakeResult
		err error
	}
	done := make(chan result, 1)
	go func() {
		res, err := r.sess.PerformServerHandshake("edge-1", "test", "example.com", 0, 0, v, nil)
		done <- result{res, err}
	}()
	r.send(t, proto.FrameHello, proto.HelloRequest{ProtocolMajor: uint32(proto.CurrentMajor)})
	var ack proto.HelloAck
	if err := proto.Unmarshal(r.read(t).Payload, &ack); err != nil {
		t.Fatal(err)
	}
	r.send(t, proto.FrameAuth, auth)
	var resp proto.AuthResponse
	if err := proto.Unmarshal(r.read(t).Payload, &resp); err != nil {
		t.Fatal(err)
	}
	select {
	case out := <-done:
		return out.res, out.err, ack, resp
	case <-time.After(5 * time.Second):
		t.Fatal("the handshake did not finish")
		return HandshakeResult{}, nil, ack, resp
	}
}

// calabi.net's edges sign clients in by token, through the handshake that also
// takes grants: no challenge is sent, the token decides, and a grant a client
// might send is not a way in.
func TestTokenHandshakeIsCalabiNetsRoute(t *testing.T) {
	r := newEdgeRig(t)
	res, err, ack, resp := r.tokenHandshake(t, testTokens{"tk_good"}, proto.AuthRequest{Token: "tk_good", ClientName: "laptop"})
	if err != nil || resp.Error != nil {
		t.Fatalf("a good token was refused: %v / %+v", err, resp.Error)
	}
	if len(ack.AuthChallenge) != 0 {
		t.Fatal("a token edge sent a grant challenge")
	}
	if res.TenantID != "42" || resp.TenantID != "42" || res.ClientID != "client-9" {
		t.Fatalf("result %+v / %+v, want the verifier's tenant and client", res, resp)
	}

	coord, dev := newTestCoord(t), newTestDevice(t)
	for name, auth := range map[string]proto.AuthRequest{
		"a wrong token": {Token: "tk_bad"},
		"no token":      {},
		"a grant instead of a token": {Grant: coord.grant(t, dev.key, 7, time.Now().Add(time.Hour)),
			Proof: []byte("not a proof")},
	} {
		r := newEdgeRig(t)
		_, err, _, resp := r.tokenHandshake(t, testTokens{"tk_good"}, auth)
		if err == nil || resp.Error == nil {
			t.Errorf("%s: signed in (err %v, resp %+v)", name, err, resp)
		}
	}
}
