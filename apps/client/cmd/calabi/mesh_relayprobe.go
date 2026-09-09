package main

import (
	"context"
	"fmt"
	"time"

	"github.com/calabi/calabi/apps/client/internal/localweb"
	"github.com/calabi/calabi/apps/client/internal/mesh"
	"github.com/calabi/calabi/apps/client/internal/mesh/derp"
	"github.com/calabi/calabi/apps/client/internal/platform/statusapi"
)

// Leg probing, from the daemon down to the relay link and back up to both
// status APIs. See internal/mesh/derp/probe.go for why it runs on the live link
// instead of dialing one of its own.

// probeLimits keeps a query string from turning into a denial of service on the
// node's own relay link. The handler already bounds the duration; these bound
// the rest, in ONE place rather than once per daemon kind — two copies of a
// clamp is two chances for them to disagree.
func clampProbeArgs(size int, rateMbps float64, seconds int) (int, float64, int) {
	if size < 16 {
		size = 16
	}
	if size > 60000 { // under MaxDERPFrameLen, with room for the framing
		size = 60000
	}
	if rateMbps < 0 {
		rateMbps = 0
	}
	if rateMbps > 10000 {
		rateMbps = 10000
	}
	if seconds < 1 {
		seconds = 1
	}
	if seconds > 60 {
		seconds = 60
	}
	return size, rateMbps, seconds
}

// probeRelayLeg drives the datapath's relay link and shapes the result for the
// status APIs. Shared by both daemon kinds so the two cannot drift.
func probeRelayLeg(ctx context.Context, dp *mesh.WGDatapath, relay string, size int, rateMbps float64, seconds int, oneWay bool) (localweb.MeshRelayProbe, error) {
	if dp == nil {
		return localweb.MeshRelayProbe{}, fmt.Errorf("mesh is not running on this node")
	}
	size, rateMbps, seconds = clampProbeArgs(size, rateMbps, seconds)
	res, addr, err := dp.ProbeRelay(ctx, relay, derp.ProbeOpts{
		Size: size, RateMbps: rateMbps, Duration: time.Duration(seconds) * time.Second, OneWay: oneWay,
	})
	if err != nil {
		return localweb.MeshRelayProbe{}, err
	}
	return shapeProbe(addr, res), nil
}

func shapeProbe(addr string, r *derp.ProbeResult) localweb.MeshRelayProbe {
	us := func(d time.Duration) uint64 { return uint64(d / time.Microsecond) }
	out := localweb.MeshRelayProbe{
		Relay:     addr,
		Sent:      r.Sent,
		Echoed:    r.Echoed,
		Bytes:     r.Bytes,
		OneWay:    r.OneWay,
		ElapsedMs: uint64(r.Elapsed / time.Millisecond),
		BlockedMs: uint64(r.Blocked / time.Millisecond),
	}
	if len(r.RTTs) > 0 {
		out.RTTMinUs = us(r.RTTs[0])
		out.RTTP50Us = us(r.Quantile(0.5))
		out.RTTP90Us = us(r.Quantile(0.9))
		out.RTTMaxUs = us(r.RTTs[len(r.RTTs)-1])
	}
	return out
}

// ProbeRelayLeg implements localweb.MeshSource for the local daemon.
func (r *meshRunner) ProbeRelayLeg(ctx context.Context, relay string, size int, rateMbps float64, seconds int, oneWay bool) (localweb.MeshRelayProbe, error) {
	return probeRelayLeg(ctx, r.datapath(), relay, size, rateMbps, seconds, oneWay)
}

// ProbeRelayLeg implements statusapi.MeshStatusSource for the platform daemon —
// the kind every installed machine actually runs, which is exactly why the
// diagnostic has to exist on both and be the same code underneath.
func (c *platformMeshController) ProbeRelayLeg(ctx context.Context, relay string, size int, rateMbps float64, seconds int, oneWay bool) (statusapi.MeshRelayProbe, error) {
	c.mu.Lock()
	lease := c.lease
	c.mu.Unlock()
	if lease == nil {
		return statusapi.MeshRelayProbe{}, fmt.Errorf("mesh is not running on this node")
	}
	got, err := lease.probeRelayLeg(ctx, relay, size, rateMbps, seconds, oneWay)
	return statusapi.MeshRelayProbe(got), err
}

// probeRelayLeg implements meshLease.
func (r *meshRunner) probeRelayLeg(ctx context.Context, relay string, size int, rateMbps float64, seconds int, oneWay bool) (localweb.MeshRelayProbe, error) {
	return probeRelayLeg(ctx, r.datapath(), relay, size, rateMbps, seconds, oneWay)
}
