package rpc

import (
	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	"github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"testing"
)

func TestRDPOwnershipIsRecipientSpecific(t *testing.T) {
	n := &core.Node{OwnerUserID: 8}
	base := &meshpb.Peer{NodeId: 6}
	for _, owner := range []int64{8, 7, 0, 8} {
		got := peerForOwner(owner, n, base)
		if got.SameOwner != (owner == 8) || base.SameOwner {
			t.Fatal("shared peer leaked recipient ownership", owner)
		}
	}
	n.OwnerUserID = 0
	if peerForOwner(0, n, base).SameOwner {
		t.Fatal("unattributed devices matched")
	}
}
