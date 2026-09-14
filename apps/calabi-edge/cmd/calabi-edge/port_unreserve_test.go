// port_unreserve_test.go — a DELETE is the one event that frees a reserved
// remote port again.
//
// Every successful claim now reserves its port for the life of the edge
// process (session.PortAllocator.Reserve), because a proxy closing does not
// delete its tunnel row and the row goes on holding the number. That leaves
// exactly one event that legitimately frees it: the row being deleted. Without
// this wiring the pool is still CORRECT — it just leaks a number per deleted
// port tunnel until the next restart re-seeds it from the DB.
//
// It is wiring, so it is tested as wiring: the assertions run through
// routeApplier.OnLocalDelta, not through PortPool.Unreserve. A pool method
// nobody calls would pass a test of the method and leak in production.
//
// RUN: go test./apps/calabi-edge/cmd/calabi-edge/ -run TestLocalDelta -v
package main

import (
	"io"
	"log/slog"
	"testing"

	"github.com/calabi/calabi/apps/calabi-edge/internal/platform/configclient"
	"github.com/calabi/calabi/apps/calabi-edge/internal/router"
)

const testEdgeID = int64(1000400000)

// A pool in the state the edge is in after a claim: 20000 is held by a live
// row, so Allocate skips it.
func poolHolding20000(t *testing.T) *router.PortPool {
	t.Helper()
	p := router.NewPortPool(20000, 20999)
	p.Reserve(20000)
	return p
}

func applierWith(p *router.PortPool) *routeApplier {
	return &routeApplier{
		edgeNodeID: testEdgeID,
		index:      &tunnelIDIndex{},
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		ports:      p,
	}
}

func portDelta(kind string) configclient.Delta {
	return configclient.Delta{
		Kind: kind,
		Route: configclient.Route{
			ID: 28, Name: "test-udp01", Type: "udp",
			RemotePort: 20000, EdgeNodeID: testEdgeID,
		},
	}
}

func TestLocalDeltaDeleteReturnsTheRowsPortToThePool(t *testing.T) {
	pool := poolHolding20000(t)
	applierWith(pool).OnLocalDelta(portDelta("delete"))

	got, ok := pool.Allocate()
	if !ok {
		t.Fatal("pool reports exhausted")
	}
	if got != 20000 {
		t.Fatalf("Allocate = %d, want 20000 back — the row that held it was "+
			"deleted, so the number is free and must not stay burned until "+
			"the next restart", got)
	}
}

// The control, and the more important half: a proxy closing, a config edit, a
// reconnect all arrive as upserts. None of them means the row is gone.
func TestLocalDeltaUpsertKeepsThePortReserved(t *testing.T) {
	pool := poolHolding20000(t)
	applierWith(pool).OnLocalDelta(portDelta("upsert"))

	got, ok := pool.Allocate()
	if !ok {
		t.Fatal("pool reports exhausted")
	}
	if got == 20000 {
		t.Fatal("an upsert freed a port that a live row still holds — this is " +
			"the collision that refuses the next claim with " +
			"\"edge=... port=20000 already bound\"")
	}
}
