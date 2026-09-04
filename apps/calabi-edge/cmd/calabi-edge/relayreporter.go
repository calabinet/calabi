package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/calabi/calabi/pkg/relay"
)

// relayUsageSubject is where a merged node re-sends its OWN relay usage. In
// cluster mode it lands on the real NATS (metering-svc consumes it directly); in
// BYOI/bff-edge mode the bffedgeclient bus maps it to the ReportRelayUsage RPC.
const relayUsageSubject = "calabi.usage.relay"

// relayUsageMsg is the JSON shape on relayUsageSubject — matches
// metering-svc's RelayReport and calabi-coord's sink. ts is the unix minute the
// running total belongs to; metering-svc MAX-merges per (org, region, minute).
type relayUsageMsg struct {
	OrgID    int64  `json:"org_id"`
	Region   string `json:"region"`
	TS       int64  `json:"ts"`
	BytesIn  int64  `json:"bytes_in"`
	BytesOut int64  `json:"bytes_out"`
}

// relayUsageReporter accumulates a merged node's OWN relay bytes into per-(org,
// region) RUNNING TOTALS for the current minute and publishes them (edge/derp
// merge + platform per-org attribution).
//
// It re-sends the running total rather than raw deltas because metering-svc
// MAX-merges per (org, region, minute): publishing each TakeUsage delta would
// have every delta overwrite the last and lose data. This is exactly what
// calabi-coord's relay sink does for platform relays.
//
// classify maps one drained delta to the (org, region) it is billed under, or
// ok=false to drop it. That one function is the whole difference between a
// self-hosted relay (single-tenant: every delta → the node's org, a "self-<label>"
// region excluded from the cap) and a platform relay (multi-tenant: each delta →
// the meshnet its grant proved, a plain region counted toward the cap; bytes with
// no grant are unattributable and dropped rather than misbilled).
//
// Core type: it publishes through the usagePublisher INTERFACE below (real NATS
// in cluster mode, the bff-edge-backed bus in BYOI mode) and imports no platform
// package, so it stays on the edge's ciphertext-only side.
// usagePublisher is the ONE method this reporter needs from the event bus.
// Declared locally rather than importing pkg/eventbus: that package carries the
// platform's NATS subject names and payload shapes and must never reach the
// public tree, while this file is core and
// ships. eventbus.Bus satisfies it structurally, so the platform wiring passes
// its bus unchanged.
type usagePublisher interface {
	Publish(subject string, payload []byte) error
}

type relayUsageReporter struct {
	bus      usagePublisher
	classify func(relay.UsageDelta) (org int64, region string, ok bool)
	logger   *slog.Logger

	mu      sync.Mutex
	minute  int64 // unix-minute the open buckets belong to
	buckets map[usageBucketKey]*usageAccum
}

type usageBucketKey struct {
	org    int64
	region string
}

type usageAccum struct{ in, out uint64 }

// newRelayUsageReporter builds a SELF-HOSTED reporter: every delta is billed to
// the one fixed org under a fixed "self-<label>" region. The org is 0 for a BYOI
// node in bff-edge mode (bff-edge stamps it from the mTLS cert) and the cluster
// fallback otherwise. Attribution needs no grant here — a single-tenant relay's
// traffic is all one org's by construction.
func newRelayUsageReporter(bus usagePublisher, orgID int64, region string, logger *slog.Logger) *relayUsageReporter {
	return &relayUsageReporter{
		bus:    bus,
		logger: logger,
		classify: func(relay.UsageDelta) (int64, string, bool) {
			return orgID, region, true
		},
	}
}

// newPlatformRelayUsageReporter builds a PLATFORM reporter: it serves many orgs,
// so each delta is billed to the meshnet its R0' grant proved, under the platform
// region code. A delta with meshnet 0 (auth off / no grant) is unattributable and
// dropped — misbilling it to a wrong or zero org is worse than not counting it.
func newPlatformRelayUsageReporter(bus usagePublisher, region string, logger *slog.Logger) *relayUsageReporter {
	return &relayUsageReporter{
		bus:    bus,
		logger: logger,
		classify: func(d relay.UsageDelta) (int64, string, bool) {
			if d.Meshnet == 0 {
				return 0, "", false
			}
			return d.Meshnet, region, true
		},
	}
}

// record folds the latest drained deltas into the current minute's per-(org,
// region) running totals and publishes every bucket that changed. A new minute
// resets the buckets first — the previous minute's last publish already carried
// its final totals, and metering keys on the minute, so the two never overwrite
// each other. A failed publish keeps the bytes in the running total to re-send
// next tick: nothing is lost.
func (r *relayUsageReporter) record(deltas []relay.UsageDelta, now time.Time) {
	m := now.UTC().Truncate(time.Minute).Unix()
	r.mu.Lock()
	if m != r.minute {
		r.minute = m
		r.buckets = nil
	}
	if r.buckets == nil {
		r.buckets = make(map[usageBucketKey]*usageAccum)
	}
	touched := make(map[usageBucketKey]struct{})
	for _, d := range deltas {
		if d.BytesIn == 0 && d.BytesOut == 0 {
			continue
		}
		org, region, ok := r.classify(d)
		if !ok {
			continue
		}
		k := usageBucketKey{org: org, region: region}
		b := r.buckets[k]
		if b == nil {
			b = &usageAccum{}
			r.buckets[k] = b
		}
		b.in += d.BytesIn
		b.out += d.BytesOut
		touched[k] = struct{}{}
	}
	type pending struct {
		k   usageBucketKey
		in  uint64
		out uint64
	}
	out := make([]pending, 0, len(touched))
	for k := range touched {
		b := r.buckets[k]
		out = append(out, pending{k: k, in: b.in, out: b.out})
	}
	minute := r.minute
	r.mu.Unlock()

	for _, p := range out {
		payload, err := json.Marshal(relayUsageMsg{
			OrgID: p.k.org, Region: p.k.region, TS: minute,
			BytesIn: clampU64(p.in), BytesOut: clampU64(p.out),
		})
		if err != nil {
			continue // unreachable for these field types
		}
		if err := r.bus.Publish(relayUsageSubject, payload); err != nil {
			r.logger.Warn("relay usage publish failed; will re-send the running total",
				"org", p.k.org, "region", p.k.region, "err", err)
		}
	}
}

// reportLoop drains the hub and reports the running total once a minute, matching
// metering-svc's per-minute buckets. A final flush on shutdown books the tail.
func (r *relayUsageReporter) reportLoop(ctx context.Context, take func() []relay.UsageDelta) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			r.record(take(), time.Now())
			return
		case <-t.C:
			r.record(take(), time.Now())
		}
	}
}

// clampU64 caps a byte count at the int64 range. Relay bytes per minute never
// approach this; the guard only avoids a wrap-around from a bug upstream.
func clampU64(v uint64) int64 {
	const max = int64(1) << 62
	if v > uint64(max) {
		return max
	}
	return int64(v)
}
