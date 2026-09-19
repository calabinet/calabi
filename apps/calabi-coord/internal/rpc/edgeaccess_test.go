package rpc

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
	meshpb "github.com/calabi/calabi/pkg/mesh-proto/meshpb"
)

// fixedEdges is a core.EdgeDirectory with a set answer.
type fixedEdges []core.Edge

func (f fixedEdges) Edges() []core.Edge { return f }

const testEdgePin = "sha256:0000000000000000000000000000000000000000000000000000000000000001"

// A device learns where to serve tunnels and gets a grant the edge — the same
// program as the relay, checking the same signature — accepts for THIS device,
// on its live session or, with its mesh switched off, on a view token.
func TestEdgeAccessGivesTheEdgeAndAGrantForTheCaller(t *testing.T) {
	r := startSelfHostedServer(t, nil)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	r.coord.RelayGrants = &core.SigningRelayGrantIssuer{Key: priv}
	r.coord.Edges = fixedEdges{{Addr: "edge.example.com:7443", Pin: testEdgePin}}
	ctx := context.Background()
	laptop := enroll(t, r.c, "file-key", "laptop")
	view, err := openView(ctx, r.c, laptop)
	if err != nil {
		t.Fatal(err)
	}

	for how, tok := range map[string]string{"live session": laptop.token, "view token": view.GetViewToken()} {
		resp, err := r.c.GetEdgeAccess(ctx, &meshpb.GetEdgeAccessRequest{SessionToken: tok})
		if err != nil {
			t.Fatalf("%s: %v", how, err)
		}
		if len(resp.GetEdges()) != 1 || resp.GetEdges()[0].GetAddr() != "edge.example.com:7443" || resp.GetEdges()[0].GetPin() != testEdgePin {
			t.Fatalf("%s: edges = %v", how, resp.GetEdges())
		}
		g, err := meshproto.VerifyRelayGrant(pub, resp.GetGrant(), time.Now())
		if err != nil {
			t.Fatalf("%s: the grant does not verify with the coordinator's key: %v", how, err)
		}
		if g.Node != laptop.key || g.Meshnet != 1 {
			t.Fatalf("%s: grant is for node %s in meshnet %d, want the caller's", how, g.Node, g.Meshnet)
		}
		if !g.Scope.Permits(meshproto.RelayKindSelfHosted) {
			t.Fatalf("%s: scope %s is not accepted by a self-hosted edge", how, g.Scope)
		}
		if resp.GetGrantExpiresUnix() != g.Expiry.Unix() {
			t.Fatalf("%s: grant_expires_unix = %d, grant says %d", how, resp.GetGrantExpiresUnix(), g.Expiry.Unix())
		}
	}
}

// Nothing for a device the server has not let in or has turned away.
func TestEdgeAccessRefusesDevicesTheServerDoesNotAccept(t *testing.T) {
	r := startSelfHostedServer(t, nil)
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	r.coord.RelayGrants = &core.SigningRelayGrantIssuer{Key: priv}
	r.coord.Edges = fixedEdges{{Addr: "edge.example.com:7443", Pin: testEdgePin}}
	ctx := context.Background()

	waiting := enroll(t, r.c, "file-key", "waiting")
	if err := r.coord.Nodes.SetApproved(ctx, waiting.id, false); err != nil {
		t.Fatal(err)
	}
	// The device tells "wait" from "join again" (also FailedPrecondition) by the message.
	if _, err := r.c.GetEdgeAccess(ctx, &meshpb.GetEdgeAccessRequest{SessionToken: waiting.token}); status.Code(err) != codes.FailedPrecondition ||
		status.Convert(err).Message() != meshproto.AwaitingApproval {
		t.Fatalf("waiting for approval: err = %v, want FailedPrecondition %q", err, meshproto.AwaitingApproval)
	}

	disabled := enroll(t, r.c, "file-key", "disabled")
	if err := r.coord.Nodes.SetDisabled(ctx, disabled.id, true); err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.GetEdgeAccess(ctx, &meshpb.GetEdgeAccessRequest{SessionToken: disabled.token}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("disabled: err = %v, want PermissionDenied", err)
	}

	gone := enroll(t, r.c, "file-key", "gone")
	view, err := openView(ctx, r.c, gone)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.SignOut(ctx, &meshpb.SignOutRequest{SessionToken: gone.token}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.GetEdgeAccess(ctx, &meshpb.GetEdgeAccessRequest{SessionToken: view.GetViewToken()}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("signed out: err = %v, want FailedPrecondition", err)
	}
}

// A coordinator that signs nothing and knows no edge says so with empty fields,
// not an error: the device can still be in the mesh.
func TestEdgeAccessWithNothingConfigured(t *testing.T) {
	r := startSelfHostedServer(t, nil)
	ctx := context.Background()
	n := enroll(t, r.c, "file-key", "laptop")
	resp, err := r.c.GetEdgeAccess(ctx, &meshpb.GetEdgeAccessRequest{SessionToken: n.token})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.GetEdges()) != 0 || len(resp.GetGrant()) != 0 || resp.GetGrantExpiresUnix() != 0 {
		t.Fatalf("resp = %v, want empty", resp)
	}
}

// Several processes speak for one device — its daemon and each `calabi http` or
// `tcp` started beside it — and each opens its own view. Asking for challenges
// and answering them interleaved, then reading, none of them ends another's, nor
// the device's live session. It stays bounded: past maxPerNode the oldest goes.
func TestEveryProcessOfADeviceKeepsItsOwnView(t *testing.T) {
	r := startSelfHostedServer(t, nil)
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	r.coord.RelayGrants = &core.SigningRelayGrantIssuer{Key: priv}
	r.coord.Edges = fixedEdges{{Addr: "edge.example.com:7443", Pin: testEdgePin}}
	ctx := context.Background()
	laptop := enroll(t, r.c, "file-key", "laptop")
	read := func(tok string) error {
		_, err := r.c.GetEdgeAccess(ctx, &meshpb.GetEdgeAccessRequest{SessionToken: tok})
		return err
	}

	const procs = 4
	chals := make([]*meshpb.GetRegisterChallengeResponse, procs)
	for i := range chals { // every process asks before any of them answers
		if chals[i], err = r.c.GetRegisterChallenge(ctx, &meshpb.GetRegisterChallengeRequest{NodeId: laptop.id, NodeKey: laptop.key.String()}); err != nil {
			t.Fatal(err)
		}
	}
	views := make([]string, procs)
	for i, chr := range chals {
		ch, err := meshproto.ParseRegisterChallenge(chr.GetChallenge())
		if err != nil {
			t.Fatal(err)
		}
		resp, err := r.c.OpenViewSession(ctx, &meshpb.OpenViewSessionRequest{
			NodeId: laptop.id, NodeKey: laptop.key.String(), ChallengeId: chr.GetChallengeId(),
			Proof: meshproto.SealRegisterProof(ch, laptop.key, laptop.priv),
		})
		if err != nil {
			t.Fatalf("process %d: its challenge was spent by another's: %v", i, err)
		}
		views[i] = resp.GetViewToken()
	}
	for i, tok := range views {
		if err := read(tok); err != nil {
			t.Fatalf("process %d: its view was ended by another's: %v", i, err)
		}
	}
	if err := read(laptop.token); err != nil {
		t.Fatalf("the live session: %v", err)
	}

	for i := 0; i < maxPerNode; i++ {
		if _, err := openView(ctx, r.c, laptop); err != nil {
			t.Fatal(err)
		}
	}
	if err := read(views[0]); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("the oldest view after %d more: %v, want Unauthenticated", maxPerNode, err)
	}
}
