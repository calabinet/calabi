package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
	pb "github.com/calabi/calabi/pkg/hooks-proto/hookspb"
	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// Enforcing the traffic cap on mesh relays (F2).
//
// An org over its monthly cap keeps its OWN relays and loses the platform's:
// the coordinator issues its nodes a grant scoped to self-hosted relays, which
// platform relays refuse and the org's own accept. The enforcement point is the
// relay handshake and not the DERP map — removing a region would take that
// region's STUN server with it and break hole punching, i.e. cut the direct
// paths this is supposed to leave alone.
//
// "Who is over cap" is ASKED, never recomputed. metering-svc's usage-deny
// checker already owns that judgement; a second implementation here would drift
// from it, and the drift surfaces as a billing dispute.
//
// Poll only. This used to ALSO subscribe to calabi.usage.deny/allow on the
// cluster's NATS to invalidate the view the instant metering changed its mind;
// F4 dropped that subscription, because it was the second of coord's two
// pkg/eventbus uses and the coordinator cannot be published while it links the
// control plane's bus.
//
// What that costs is bounded and small: the events only ever shaved up to
// relayScopeTTL (60s) off a judgement metering itself recomputes on a 5-minute
// tick, and the direction of the resulting error is one this design already
// accepts on purpose — see For(): an org relaying for one more cycle is a cost,
// an org wrongly losing its relay fallback is an outage.
//
// What NOT keeping it buys is worth more: BillingHooks stays unary. A contract
// whose value is that a third party can implement it must not require a
// server-streaming RPC with reconnect and resync semantics to be correct.

const (
	relayScopeTTL = 60 * time.Second
	// relayScopeRetry backs off after a failed refresh so a metering outage
	// doesn't turn into a request flood.
	relayScopeRetry = 15 * time.Second
)

// relayScopeSource decides a node's relay grant scope from the set of orgs
// metering-svc currently has over cap.
type relayScopeSource struct {
	cli    pb.BillingHooksClient
	logger *slog.Logger

	mu         sync.Mutex
	denied     map[int64]bool
	nextFetch  time.Time
	refreshing bool
}

// newRelayScopeSource returns the scope function for the grant issuer, or nil
// when metering isn't configured — in which case grants stay unscoped and the
// traffic cap simply isn't enforced on relays.
func newRelayScopeSource(logger *slog.Logger) func(context.Context, *core.Node) meshproto.RelayScope {
	conn := meteringConn(logger)
	if conn == nil {
		logger.Info("coord: relay quota enforcement disabled (no CALABI_COORD_METERING_ADDR)")
		return nil
	}
	s := &relayScopeSource{cli: pb.NewBillingHooksClient(conn), logger: logger, denied: map[int64]bool{}}
	logger.Info("coord: relay quota enforcement enabled", "ttl", relayScopeTTL)
	return s.For
}

// For is called while a netmap is being built, so it NEVER blocks: it answers
// from the current view and refreshes in the background when that view is stale.
//
// The first call before any fetch lands therefore reports "not denied". That is
// the intended failure direction — an org wrongly losing its relay fallback is a
// visible outage, while an org relaying for one more cycle is a cost. The same
// reasoning keeps the previous view on a refresh error rather than clearing it:
// a metering outage freezes enforcement, it does not grant an amnesty.
func (s *relayScopeSource) For(_ context.Context, node *core.Node) meshproto.RelayScope {
	if node == nil {
		return meshproto.RelayScopeAll
	}
	s.mu.Lock()
	denied := s.denied[int64(node.Meshnet)]
	stale := time.Now().After(s.nextFetch)
	if stale && !s.refreshing {
		s.refreshing = true
		go s.refresh()
	}
	s.mu.Unlock()

	if denied {
		return meshproto.RelayScopeSelfHosted
	}
	return meshproto.RelayScopeAll
}

func (s *relayScopeSource) refresh() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := s.cli.ListDeniedOrgs(ctx, &pb.ListDeniedOrgsRequest{})

	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshing = false
	if err != nil {
		s.nextFetch = time.Now().Add(relayScopeRetry)
		s.logger.Warn("coord: cannot read the over-cap org list; keeping the previous view", "err", err)
		return
	}
	next := make(map[int64]bool, len(resp.GetOrgIds()))
	for _, id := range resp.GetOrgIds() {
		next[id] = true
	}
	if len(next) != len(s.denied) {
		s.logger.Info("coord: over-cap org set changed", "orgs", len(next))
	}
	s.denied = next
	s.nextFetch = time.Now().Add(relayScopeTTL)
}

// meteringConn is the process-wide connection to metering-svc, dialed once.
//
// It is the ONE address the coordinator needs from a platform for billing: the
// quota source above asks it who is over cap, and the usage sink
// (relayusagesink_platform.go) reports what the relays moved. Both are
// BillingHooks on the same port, so a second connection would be pure waste.
//
// Returns nil when CALABI_COORD_METERING_ADDR is unset — a self-hosted coordinator
// never sets it, and both callers degrade to doing nothing rather than failing.
// A dial error is also nil and NOT fatal: the coordinator's job is the mesh, and
// losing billing costs the platform money while losing the coordinator costs
// everyone their network.
var (
	meteringOnce sync.Once
	meteringCC   *grpc.ClientConn
)

func meteringConn(logger *slog.Logger) *grpc.ClientConn {
	meteringOnce.Do(func() {
		addr := env("METERING_ADDR")
		if addr == "" {
			return
		}
		cc, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			logger.Error("coord: cannot dial metering; relay quota enforcement and "+
				"usage reporting are both disabled", "addr", addr, "err", err)
			return
		}
		logger.Info("coord: metering connection ready", "addr", addr)
		meteringCC = cc
	})
	return meteringCC
}
