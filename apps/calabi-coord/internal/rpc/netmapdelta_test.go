package rpc

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestDeltaRefreshChecksAuthorizationAndUpdatesSignedGrant(t *testing.T) {
	s, st, nodes, e := sharedMapFixture(t)
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	s.coord.RelayGrants = &core.SigningRelayGrantIssuer{Key: key, Now: func() time.Time { return now }}
	raw := &snapshotStream{ctx: context.Background()}
	stream := &deltaNetMapStream{Coordinator_PullNetMapServer: raw}
	if err = s.sendNetMap(stream, nodes[0], e, false); err != nil {
		t.Fatal(err)
	}
	if raw.sent.Delta || raw.sent.Sequence != 1 {
		t.Fatal("first frame is not full")
	}
	now = now.Add(15 * time.Minute)
	if err = s.sendNetMap(stream, nodes[0], e, true); err != nil {
		t.Fatal(err)
	}
	if !raw.sent.GrantOnly || len(raw.sent.Peers) != 0 {
		t.Fatal("grant refresh sent topology")
	}
	g, err := meshproto.VerifyRelayGrant(key.Public().(ed25519.PublicKey), raw.sent.RelayGrant, now)
	if err != nil || g.Node != nodes[0].NodeKey || !g.Expiry.Equal(now.Add(core.RelayGrantTTL)) {
		t.Fatalf("bad renewed grant: %v", err)
	}
	// Force authoritative reread without a notification, as at a later refresh.
	e.mu.Lock()
	e.loaded = time.Time{}
	e.mu.Unlock()
	if err = st.SetDisabled(context.Background(), nodes[0].ID, true); err != nil {
		t.Fatal(err)
	}
	if err = s.sendNetMap(stream, nodes[0], e, true); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("disabled device renewed: %v", err)
	}
}

func TestDeltaSupersededFrameDoesNotAdvanceBaseline(t *testing.T) {
	raw := &snapshotStream{ctx: context.Background()}
	changed := make(chan struct{})
	close(changed)
	s := &deltaNetMapStream{Coordinator_PullNetMapServer: raw, changed: changed}
	m := &meshpb.NetMap{Self: &meshpb.Peer{NodeId: 1}}
	if err := s.Send(m); !errors.Is(err, errMapSuperseded) || raw.sent != nil {
		t.Fatal("sent superseded frame", err)
	}
	s.changed = nil
	if err := s.Send(m); err != nil || raw.sent.Sequence != 1 || raw.sent.Delta {
		t.Fatal("superseded frame advanced baseline", err)
	}
}

func TestDeltaProtocolMixedClientsAndRollback(t *testing.T) {
	for _, rollback := range []string{"", "full", "legacy"} {
		t.Run(rollback, func(t *testing.T) {
			t.Setenv("CALABI_COORD_FULL_NETMAP", "")
			t.Setenv("CALABI_COORD_LEGACY_NETMAP", "")
			if rollback == "full" {
				t.Setenv("CALABI_COORD_FULL_NETMAP", "1")
			}
			if rollback == "legacy" {
				t.Setenv("CALABI_COORD_LEGACY_NETMAP", "1")
			}
			client := startTestServer(t)
			nodes := make([]testNode, 12)
			for i := range nodes {
				nodes[i] = enroll(t, client, devKey, "device")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			old, err := client.PullNetMap(ctx, &meshpb.PullNetMapRequest{NodeId: nodes[0].id, SessionToken: nodes[0].token})
			if err != nil {
				t.Fatal(err)
			}
			modern, err := client.PullNetMap(ctx, &meshpb.PullNetMapRequest{NodeId: nodes[1].id, SessionToken: nodes[1].token, DeltaNetmap: true})
			if err != nil {
				t.Fatal(err)
			}
			legacyFirst, err := old.Recv()
			if err != nil {
				t.Fatal(err)
			}
			first, err := modern.Recv()
			if err != nil {
				t.Fatal(err)
			}
			if legacyFirst.Sequence != 0 || legacyFirst.Delta || first.Delta || len(first.Peers) != 11 {
				t.Fatal("bad compatibility snapshot")
			}
			if (first.Sequence == 1) != (rollback == "") {
				t.Fatal("rollback did not disable P4")
			}
			_, err = client.ReportEndpoints(ctx, &meshpb.ReportEndpointsRequest{NodeId: nodes[2].id, SessionToken: nodes[2].token, Endpoints: []string{"192.0.2.20:41641"}})
			if err != nil {
				t.Fatal(err)
			}
			oldMap, err := old.Recv()
			if err != nil {
				t.Fatal(err)
			}
			frame, err := modern.Recv()
			if err != nil {
				t.Fatal(err)
			}
			if oldMap.Delta || oldMap.Sequence != 0 || len(oldMap.Peers) != 11 {
				t.Fatal("old client received a delta")
			}
			if rollback != "" {
				if frame.Delta || len(frame.Peers) != 11 {
					t.Fatal("rollback did not send full map")
				}
				return
			}
			if !frame.Delta || len(frame.Peers) != 1 || frame.BaseSequence != 1 || frame.Peers[0].NodeId != nodes[2].id {
				t.Fatalf("wrong peer patch: %v", frame)
			}
			var decoder meshproto.NetMapDecoder
			if _, _, err = decoder.Apply(first); err != nil {
				t.Fatal(err)
			}
			merged, _, err := decoder.Apply(frame)
			if err != nil || len(merged.Peers) != 11 {
				t.Fatalf("bad reconstructed graph: %v", err)
			}
		})
	}
}
