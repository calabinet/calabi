package relay

// A relay that one organization runs for itself admits that organization's
// devices and nobody else's (AuthConfig.Meshnet). The coordinator it trusts signs
// grants for EVERY organization, so a device of another one arrives with a
// grant that is genuine, for a key it genuinely holds - and the signature, node
// and scope checks all pass. Only the meshnet tells them apart.
//
//   go test ./pkg/relay/ -run TestRelayOfOneMeshnet -v

import (
	"log/slog"
	"net"
	"testing"
	"time"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// tryJoin runs a genuine handshake - own key, own grant - for a node of meshnet
// and reports whether the relay kept the link.
func tryJoin(t *testing.T, h *Hub, c coord, meshnet int64) bool {
	t.Helper()
	nk, priv := nodeKeys(t)
	mine, theirs := net.Pipe()
	t.Cleanup(func() { _ = mine.Close() })
	go h.Serve(theirs)
	if err := handshake(t, mine, nk, priv, c.grantIn(t, nk, meshnet)); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	// A refused link is closed by the relay; an admitted one answers a ping.
	if err := meshproto.WriteDERPFrame(mine, meshproto.DERPFramePing, []byte("admitted")); err != nil {
		return false
	}
	_ = mine.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		typ, _, err := meshproto.ReadDERPFrame(mine)
		if err != nil {
			if h.Connected(nk) {
				t.Fatal("the relay closed the link but kept the node registered")
			}
			return false
		}
		if typ == meshproto.DERPFramePong {
			return h.Connected(nk)
		}
	}
}

func TestRelayOfOneMeshnetAdmitsOnlyThatMeshnet(t *testing.T) {
	c := newCoord(t)
	h := NewHub(slog.Default(), AuthConfig{Require: true, CoordPub: c.pub, Kind: meshproto.RelayKindSelfHosted, Meshnet: 7})

	if !tryJoin(t, h, c, 7) {
		t.Fatal("a device of the relay's own organization was turned away")
	}
	if tryJoin(t, h, c, 8) {
		t.Fatal("a device of ANOTHER organization got in with its own genuine grant")
	}
}

// The control for the test above: the same grant for meshnet 8 is admitted by a
// relay that serves every meshnet. Without it the test above would also pass on
// a relay that refused everyone from meshnet 8 for some other reason.
func TestRelayOfEveryMeshnetAdmitsAnyGrant(t *testing.T) {
	c := newCoord(t)
	h := NewHub(slog.Default(), AuthConfig{Require: true, CoordPub: c.pub, Kind: meshproto.RelayKindSelfHosted})

	for _, mn := range []int64{7, 8} {
		if !tryJoin(t, h, c, mn) {
			t.Fatalf("a relay with no meshnet of its own turned away a genuine grant for meshnet %d", mn)
		}
	}
}
