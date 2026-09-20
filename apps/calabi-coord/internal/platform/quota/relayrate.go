package quota

import (
	"context"
	"sync"
	"time"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	pb "github.com/calabinet/calabi/pkg/hooks-proto/hookspb"
)

// The relay self-limit a coordinator hands each node (core.RelayRateSource).
//
// READ THROUGH AN ADMISSION, ON PURPOSE. QuotaHooks has one method, CheckAdmit,
// and no "read me this number" RPC. Asking with current=0, delta=0 admits
// trivially and returns the plan's limit, which is the number we want. The
// alternative was a new RPC on a contract that self-hosted coordinators also
// speak — a wider surface for one field.
//
// The two kinds map to bandwidth_kbps / bandwidth_burst_kbps, the same
// PER-DEVICE pair the tunnel path uses; the org-wide relay allowance
// (org_relay_bandwidth_kbps) is deliberately NOT sent to nodes. A node cannot
// enforce a limit shared with devices it cannot see, and telling it a number it
// would then apply to itself alone would throttle every device to the whole
// org's allowance each. That tier lives on the relay, which can see all of them.
const (
	kindBandwidth      = "bandwidth_kbps"
	kindBandwidthBurst = "bandwidth_burst_kbps"
)

// relayRateTTL bounds how stale a node's self-limit may be. A netmap goes out
// on every peer change, so without a cache a busy meshnet would ask quota-svc
// twice per push. 30s matches calabi-edge's quota cache.
const relayRateTTL = 30 * time.Second

type relayRateEntry struct {
	sustained, burst uint32
	at               time.Time
}

// RelayRateKbps implements core.RelayRateSource.
//
// Degrades to (0, 0) — no self-limit — on any failure. That direction is not
// arbitrary: the relay polices the same allowance regardless, so a node that
// was told nothing is still capped, just the lossy way. A node told a number
// we are not sure of would throttle itself for a quota-svc hiccup, and every
// node in the meshnet at once.
func (c *Client) RelayRateKbps(ctx context.Context, t core.MeshnetID) (uint32, uint32) {
	if c == nil {
		return 0, 0
	}
	if s, b, ok := c.cachedRelayRate(t); ok {
		return s, b
	}
	sustained := c.planLimit(ctx, t, kindBandwidth)
	if sustained <= 0 {
		// No sustained rate = nothing to pace against; a burst ceiling alone
		// would be a cap with no floor under it.
		c.storeRelayRate(t, 0, 0)
		return 0, 0
	}
	burst := c.planLimit(ctx, t, kindBandwidthBurst)
	if burst < 0 {
		burst = 0
	}
	c.storeRelayRate(t, uint32(sustained), uint32(burst))
	return uint32(sustained), uint32(burst)
}

// planLimit asks quota-svc for one dimension's value. Returns -1 for unlimited
// or unknown, which callers treat as "do not send a limit".
func (c *Client) planLimit(ctx context.Context, t core.MeshnetID, kind string) int64 {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, err := c.rpc.CheckAdmit(ctx, &pb.CheckAdmitRequest{
		OrgId: int64(t), Kind: kind, Current: 0, Delta: 0,
	})
	if err != nil {
		c.logger.Warn("relay rate lookup failed; sending no self-limit",
			"meshnet", int64(t), "kind", kind, "err", err)
		return -1
	}
	// A refusal at current=0/delta=0 means the kind is not registered on this
	// quota-svc (an older one). Same answer as an error: send nothing.
	if !resp.GetAllowed() {
		return -1
	}
	return resp.GetLimit()
}

func (c *Client) cachedRelayRate(t core.MeshnetID) (uint32, uint32, bool) {
	c.rateMu.Lock()
	defer c.rateMu.Unlock()
	e, ok := c.rateCache[t]
	if !ok || time.Since(e.at) > relayRateTTL {
		return 0, 0, false
	}
	return e.sustained, e.burst, true
}

func (c *Client) storeRelayRate(t core.MeshnetID, sustained, burst uint32) {
	c.rateMu.Lock()
	defer c.rateMu.Unlock()
	if c.rateCache == nil {
		c.rateCache = make(map[core.MeshnetID]relayRateEntry)
	}
	c.rateCache[t] = relayRateEntry{sustained: sustained, burst: burst, at: time.Now()}
}

// rateCacheFields is embedded in Client (quota.go) — declared here so the
// cache's whole implementation stays in one file.
type rateCacheFields struct {
	rateMu    sync.Mutex
	rateCache map[core.MeshnetID]relayRateEntry
}
