package main

import (
	"context"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
	pb "github.com/calabi/calabi/pkg/hooks-proto/hookspb"
)

// Deriving the platform DERP map from the edge directory (edge/derp merge).
//
// Since calabi-edge grew a relay role (role=relay|both), a platform relay IS a
// platform edge. Rather than maintain a SECOND relay registry (a hand-kept
// derp-map.json), coord reads identity-svc's edge directory — the one place
// every edge already registers on boot — and builds its platform DERP map from
// the rows that advertise a relay port. One source of truth: the edge configs.
//
// The static CALABI_COORD_DERP_ADDR / CALABI_COORD_DERP_MAP_FILE map stays as the
// FALLBACK: it is what a deployment gets before any edge has reported a relay
// (fresh boot) or if identity-svc can't be reached, so the fleet is never left
// with an empty map. Once edges report relay ports, they take over.

const (
	// edgeDERPRefresh is how often coord re-reads the edge directory. Edges
	// heartbeat it every ~30s; polling at the same cadence surfaces a newly
	// online (or moved) platform relay within a heartbeat without hammering
	// identity-svc.
	edgeDERPRefresh = 30 * time.Second
	// edgeDERPFreshnessSec is the freshness window coord asks ListEdges for —
	// identity-svc's default (90s = 3× heartbeat). A relay that has missed three
	// heartbeats drops out of the map, so nodes stop homing on a dead endpoint.
	edgeDERPFreshnessSec = 90
)

// edgeLister is the slice of identity-svc's client coord needs here. Satisfied
// by pb.IdentityHooksClient. Kept narrow so a test can fake it.
type edgeLister interface {
	ListRelayEndpoints(ctx context.Context, in *pb.ListRelayEndpointsRequest, opts ...grpc.CallOption) (*pb.ListRelayEndpointsResponse, error)
}

// dialEdgeLister connects to identity-svc for edge-directory reads (same address
// as auth, CALABI_COORD_IDENTITY_ADDR). A separate lazy conn keeps the auth client
// narrow. This is an in-cluster hop and stays plaintext — unlike coord's PUBLIC
// gRPC, which the daemon dials over TLS (see svcboot ServerOptions / R0′).
func dialEdgeLister(addr string) (edgeLister, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return pb.NewIdentityHooksClient(conn), nil
}

// platformDERPFromEdges is coord's live platform DERP map, rebuilt from the edge
// directory on a fixed cadence. Its Current method feeds CompositeDERP.PlatformFn.
type platformDERPFromEdges struct {
	lister   edgeLister
	fallback core.DERPMap
	logger   *slog.Logger

	mu   sync.RWMutex
	live core.DERPMap
}

func newPlatformDERPFromEdges(lister edgeLister, fallback core.DERPMap, logger *slog.Logger) *platformDERPFromEdges {
	// Start on the static fallback so the very first netmaps have a map even
	// before the first edge poll completes.
	return &platformDERPFromEdges{lister: lister, fallback: fallback, logger: logger, live: fallback}
}

// Current returns the platform DERP map CompositeDERP should use right now.
func (p *platformDERPFromEdges) Current() core.DERPMap {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.live
}

// refresh re-reads the edge directory and swaps in a new platform map when it
// changed, returning true so the caller re-pushes netmaps. On ANY error it keeps
// the previous map — an identity-svc blip must never blank the fleet's relays
// out from under live nodes.
func (p *platformDERPFromEdges) refresh(ctx context.Context) bool {
	resp, err := p.lister.ListRelayEndpoints(ctx, &pb.ListRelayEndpointsRequest{FreshnessSeconds: edgeDERPFreshnessSec})
	if err != nil {
		p.logger.Warn("coord: cannot list edges for the DERP map; keeping the previous map", "err", err)
		return false
	}
	next := buildDERPFromEdges(resp.GetItems(), p.fallback)
	p.mu.Lock()
	changed := !derpMapEqual(p.live, next)
	if changed {
		p.live = next
	}
	p.mu.Unlock()
	return changed
}

// run primes the map, then refreshes on a fixed cadence until ctx ends,
// re-pushing every node's netmap whenever the platform map changed so a new or
// moved relay is picked up without a reconnect (mirrors startPolicyWatcher).
func (p *platformDERPFromEdges) run(ctx context.Context, notif *core.Notifier) {
	if p.refresh(ctx) {
		notif.BumpAll()
	}
	t := time.NewTicker(edgeDERPRefresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if p.refresh(ctx) {
				p.logger.Info("coord: platform DERP map changed; re-pushing netmaps")
				notif.BumpAll()
			}
		}
	}
}

// buildDERPFromEdges turns edge-directory rows into a platform DERP map: one
// region per distinct region code, one node per relay-running edge. Edges with
// relay_derp_port == 0 run no relay and are skipped; a merged node's relay host
// is the host portion of its public_addr (control + relay share one host). When
// NO edge advertises a relay the static fallback is returned, so a deployment
// keeps whatever CALABI_COORD_DERP_ADDR / _MAP_FILE named until edges take over.
func buildDERPFromEdges(edges []*pb.RelayEndpoint, fallback core.DERPMap) core.DERPMap {
	byRegion := map[string][]core.DERPNode{}
	for _, e := range edges {
		if e.GetDerpPort() <= 0 {
			continue
		}
		host := hostOnly(e.GetHost())
		if host == "" || e.GetRegion() == "" {
			continue
		}
		byRegion[e.GetRegion()] = append(byRegion[e.GetRegion()], core.DERPNode{
			HostName: host,
			DERPPort: int(e.GetDerpPort()),
			STUNPort: int(e.GetStunPort()),
		})
	}
	if len(byRegion) == 0 {
		return fallback
	}
	codes := make([]string, 0, len(byRegion))
	for code := range byRegion {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	out := core.DERPMap{}
	for _, code := range codes {
		nodes := byRegion[code]
		// Deterministic order so derpMapEqual doesn't see churn from map iteration.
		sort.Slice(nodes, func(i, j int) bool {
			if nodes[i].HostName != nodes[j].HostName {
				return nodes[i].HostName < nodes[j].HostName
			}
			return nodes[i].DERPPort < nodes[j].DERPPort
		})
		out.Regions = append(out.Regions, core.DERPRegion{Code: code, Nodes: nodes})
	}
	return out
}

// hostOnly returns the host portion of a "host:port"; a bare host (no port) is
// returned unchanged. A relay is reached at host(public_addr):relay_derp_port.
func hostOnly(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// derpMapEqual reports whether two maps carry the same regions and nodes in the
// same order, so a steady-state refresh doesn't needlessly re-push every netmap.
// Both inputs come from buildDERPFromEdges (sorted) or are the same fallback
// value, so an order-sensitive compare is sufficient.
func derpMapEqual(a, b core.DERPMap) bool {
	if len(a.Regions) != len(b.Regions) {
		return false
	}
	for i := range a.Regions {
		ra, rb := a.Regions[i], b.Regions[i]
		if ra.Code != rb.Code || len(ra.Nodes) != len(rb.Nodes) {
			return false
		}
		for j := range ra.Nodes {
			if ra.Nodes[j] != rb.Nodes[j] {
				return false
			}
		}
	}
	return true
}
