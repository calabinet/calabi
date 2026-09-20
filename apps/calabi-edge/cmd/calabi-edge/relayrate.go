package main

import (
	"context"
	"log/slog"

	"github.com/calabinet/calabi/apps/calabi-edge/internal/ratelimit"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	"github.com/calabinet/calabi/pkg/relay"
)

// Rate limiting for the mesh relay.
//
// The relay hub knows nothing about plans or quota-svc — it takes a resolver
// (pkg/relay/rate.go) and calls it once per link. This file is that resolver:
// it turns "which org is this link" into two token buckets, the device's own
// and the org-wide one, and hands them over as a relay.RateLimiter.
//
// WHAT THIS TIER IS FOR, given the client is supposed to limit itself first:
// the client runs on the customer's machine and its source is public, so
// self-limiting is cooperation, not enforcement. This is the enforcement. When
// the client does its part the buckets here never empty and not one frame is
// dropped; when it doesn't, the relay stops carrying the excess.

// relayQuotaLookup is the slice of the quota client this resolver needs.
// *quotaclient.CachedClient satisfies it, and its cache means a reconnect
// storm costs one lookup per org per TTL rather than one per link.
type relayQuotaLookup interface {
	RelayBandwidthBytesPerSec(ctx context.Context, orgID int64) (devSustained, devPeak, orgSustained, orgPeak int64)
}

// relayRateResolver resolves one mesh link's two-tier limiter.
type relayRateResolver struct {
	quota  relayQuotaLookup
	orgReg *ratelimit.OrgRegistry
	logger *slog.Logger
}

func newRelayRateResolver(q relayQuotaLookup, logger *slog.Logger) *relayRateResolver {
	if q == nil {
		return nil
	}
	return &relayRateResolver{quota: q, orgReg: ratelimit.NewOrgRegistry(), logger: logger}
}

// For implements relay.RateLimiterFor.
//
// Returns nil — no limit — whenever it cannot make a confident decision:
// meshnet 0 (auth off / no grant, so nobody to meter against) or a plan that
// sets no relay allowance. That is the same degrade-open posture the tunnel
// path takes, and for the same reason: a relay that throttles because the
// control plane blinked is worse than one that briefly does not.
func (r *relayRateResolver) For(meshnet int64, _ meshproto.NodeKey) relay.RateLimiter {
	if r == nil || meshnet <= 0 {
		return nil
	}
	dev, devPeak, org, orgPeak := r.quota.RelayBandwidthBytesPerSec(context.Background(), meshnet)
	if dev <= 0 && org <= 0 {
		return nil
	}
	link := &relayLink{}
	var deviceLim *ratelimit.Limiter
	if dev > 0 {
		// Per DEVICE, not per link: one bucket built here, held by this link,
		// gone when it disconnects. Nothing shared, nothing to release.
		deviceLim = ratelimit.New(dev, devPeak)
	}
	var orgLim *ratelimit.Limiter
	if org > 0 {
		orgLim = r.orgReg.Acquire(meshnet, org, orgPeak)
		link.release = func() { r.orgReg.Release(meshnet) }
	}
	link.Chain = ratelimit.NewChain(deviceLim, orgLim)
	if r.logger != nil {
		r.logger.Debug("relay rate limits installed",
			"meshnet", meshnet,
			"device_sustained_bytes_per_sec", dev, "device_peak_bytes_per_sec", devPeak,
			"org_sustained_bytes_per_sec", org, "org_peak_bytes_per_sec", orgPeak)
	}
	return link
}

// relayLink is one link's limiter: the two-tier Chain plus the release of the
// shared org bucket. Close is the optional half of relay.RateLimiter — the hub
// calls it when the link goes away or re-authenticates into another org.
type relayLink struct {
	*ratelimit.Chain
	release func()
}

func (l *relayLink) Close() {
	if l != nil && l.release != nil {
		l.release()
		l.release = nil
	}
}

// OrgsHeld reports how many org buckets are currently alive. Tests use it to
// prove the release path runs; nothing in production reads it yet.
func (r *relayRateResolver) OrgsHeld() int {
	if r == nil {
		return 0
	}
	return r.orgReg.Len()
}
