package rpc

import (
	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	"testing"
)

func TestWirePeersSnapshotAndGroupIsolation(t *testing.T) {
	var a, b meshMapState
	first, second := &core.NetMapSnapshot{}, &core.NetMapSnapshot{}
	ca := a.wirePeers(first)
	n := &core.Node{ID: 7, Name: "old", NodeKey: meshproto.NodeKey{1}}
	p := ca.peer(n)
	if ca.peer(n) != p {
		t.Fatal("immutable peer not shared")
	}
	// A refresh can replace data without changing a notification version.
	n.Name = "new"
	cb := a.wirePeers(second)
	if cb == ca || cb.peer(n).Name != "new" || p.Name != "old" {
		t.Fatal("refresh reused stale peer or mutated old snapshot")
	}
	other := b.wirePeers(first)
	n.NodeKey = meshproto.NodeKey{2}
	if other == ca || other.peer(n).NodeKey == p.NodeKey {
		t.Fatal("cross-group public data reused")
	}
}
