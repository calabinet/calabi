package main

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
	pb "github.com/calabi/calabi/pkg/hooks-proto/hookspb"
)

// Reporting attributed relay usage to a platform (F2; moved onto the hooks
// contract in F4).
//
// This used to publish JSON on the cluster's NATS (subject calabi.usage.relay).
// That was the LAST thing tying the coordinator to platform infrastructure, and
// it is why coord could not be published: linking pkg/eventbus meant linking the
// control plane's bus. It is now BillingHooks.ReportRelayUsage — one unary RPC
// on the same metering-svc port coord already asks "who is over cap".
//
// The wire shape is unchanged (org_id/region/ts/bytes_in/bytes_out per minute),
// and metering's NATS consumer still accepts the old subject, so a coordinator
// and a metering-svc from either side of this change interoperate in ONE
// direction: old coord + new metering works. New coord + OLD metering does not
// — the RPC is Unimplemented there — so metering-svc deploys FIRST. That skew
// is made loud rather than silent (see relayUsageMaxBuckets).

// relayUsageBucketTTL bounds how long a fully-reported minute bucket is kept.
// Buckets with unreported bytes are NEVER dropped on age — they are the only
// copy of those bytes.
const relayUsageBucketTTL = 10 * time.Minute

// relayUsageMaxBuckets caps the backlog of unreported buckets.
//
// Unbounded retention was safe while the failure mode was NATS being down —
// transient, and the backlog drains. An RPC adds a PERMANENT failure mode that
// looks identical from in here: a coordinator deployed against a metering-svc
// that predates ReportRelayUsage gets Unimplemented forever, and the backlog
// grows by (meshnets x regions) every minute until the process dies of it.
// Losing the oldest bytes is bad; losing the coordinator is worse, and one that
// OOMs hours later makes the actual cause unfindable.
//
// 10k buckets is roughly a thousand active meshnets backed up for ten minutes —
// far past any real outage, far short of memory pressure.
const relayUsageMaxBuckets = 10000

// relayUsageReportTimeout bounds one report. Generous on purpose: the batch is
// the only copy of these bytes, so waiting is cheaper than retrying.
const relayUsageReportTimeout = 20 * time.Second

// hookRelayUsageSink reports each minute bucket's RUNNING TOTAL, not the delta
// that produced it.
//
// That is what makes the pipeline safe end to end. Delivery may repeat (a retry
// after a call whose result coord never saw), so metering merges duplicates by
// keeping the larger value; a delta re-sent under that rule would be silently
// dropped, and two deltas landing in the same minute would lose the smaller.
// Reporting the running total makes both cases correct without depending on how
// often the poller runs — the same contract calabi-edge already meets by reporting
// cumulative bytes per minute.
//
// It also makes retention trivial, which matters because the bytes exist nowhere
// else once the relay's counters were reset: a failed report just leaves the
// bucket dirty, and the next round re-sends the (now larger) total. Merging by
// max means the late arrival is not a duplicate, it is a correction.
//
// ONE owner for un-acknowledged bytes. The poller holds usage it could not hand
// over; from the moment this sink accepts a batch, the buckets hold it and the
// sink reports success. Both retaining the same bytes would double-count them on
// the retry — an easy mistake, since each mechanism looks right on its own.
type hookRelayUsageSink struct {
	cli    pb.BillingHooksClient
	logger *slog.Logger
	now    func() time.Time

	mu      sync.Mutex
	buckets map[relayBucketKey]*relayBucketVal
}

type relayBucketKey struct {
	meshnet core.MeshnetID
	region  string
	minute  int64 // unix seconds, truncated to the minute
}

type relayBucketVal struct {
	bytesIn  int64
	bytesOut int64
	dirty    bool // has bytes that no report has carried yet
}

// newHookRelayUsageSink returns nil when no metering address is configured,
// which leaves the coordinator reporting nothing — the state a self-hosted
// coordinator is permanently in, and the state a platform is in until relay
// usage collection is turned on.
func newHookRelayUsageSink(logger *slog.Logger) core.RelayUsageSink {
	conn := meteringConn(logger)
	if conn == nil {
		logger.Info("coord: relay usage reporting disabled (no CALABI_COORD_METERING_ADDR)")
		return nil
	}
	logger.Info("coord: relay usage reporting enabled (BillingHooks.ReportRelayUsage)")
	return &hookRelayUsageSink{
		cli:     pb.NewBillingHooksClient(conn),
		logger:  logger,
		now:     time.Now,
		buckets: map[relayBucketKey]*relayBucketVal{},
	}
}

// RecordRelayUsage folds each record into its minute bucket and reports every
// bucket that still has unreported bytes.
//
// Always returns nil: accepting the batch transfers ownership of these bytes to
// the buckets, and telling the caller otherwise would make it retain a second
// copy. A report that fails is retried from here on the next round.
func (s *hookRelayUsageSink) RecordRelayUsage(ctx context.Context, recs []core.RelayUsageRecord) error {
	minute := s.now().UTC().Truncate(time.Minute)

	s.mu.Lock()
	for _, r := range recs {
		k := relayBucketKey{meshnet: r.Meshnet, region: r.Region, minute: minute.Unix()}
		v := s.buckets[k]
		if v == nil {
			v = &relayBucketVal{}
			s.buckets[k] = v
		}
		v.bytesIn += int64(r.BytesIn)
		v.bytesOut += int64(r.BytesOut)
		v.dirty = true
	}
	keys, samples := s.pendingLocked()
	s.mu.Unlock()

	if len(samples) > 0 {
		s.report(ctx, keys, samples)
	}

	s.mu.Lock()
	s.pruneLocked(minute)
	s.mu.Unlock()
	return nil
}

// report sends one batch and, on success, marks exactly the buckets it carried
// as clean. Bytes that arrived while the call was in flight stay dirty: they
// were not in this batch, and the next round re-sends the larger total.
func (s *hookRelayUsageSink) report(ctx context.Context, keys []relayBucketKey, samples []*pb.RelayUsageSample) {
	// WithoutCancel: the poller's context is torn down between rounds, and these
	// bytes exist nowhere else — the report must not be cancelled with it.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), relayUsageReportTimeout)
	defer cancel()
	if _, err := s.cli.ReportRelayUsage(rctx, &pb.ReportRelayUsageRequest{Samples: samples}); err != nil {
		// The whole batch stays dirty. Partial credit is not available and must
		// not be invented: the server applies samples in order and stops at the
		// first store failure, so whatever it did write gets re-sent as the
		// same-or-larger running total and merges by max.
		s.logger.Warn("coord: relay usage report failed; will re-send the running totals",
			"buckets", len(samples), "err", err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range keys {
		if v := s.buckets[k]; v != nil {
			v.dirty = false
		}
	}
}

// pendingLocked lists the buckets awaiting a report, oldest minute first so a
// backlog is reported in order, alongside the samples to send for them.
func (s *hookRelayUsageSink) pendingLocked() ([]relayBucketKey, []*pb.RelayUsageSample) {
	keys := make([]relayBucketKey, 0, len(s.buckets))
	for k, v := range s.buckets {
		if v.dirty {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].minute != keys[j].minute {
			return keys[i].minute < keys[j].minute
		}
		if keys[i].meshnet != keys[j].meshnet {
			return keys[i].meshnet < keys[j].meshnet
		}
		return keys[i].region < keys[j].region
	})
	samples := make([]*pb.RelayUsageSample, 0, len(keys))
	for _, k := range keys {
		v := s.buckets[k]
		samples = append(samples, &pb.RelayUsageSample{
			OrgId: int64(k.meshnet), Region: k.region, Ts: k.minute,
			BytesIn: v.bytesIn, BytesOut: v.bytesOut,
		})
	}
	return keys, samples
}

// pruneLocked drops reported buckets that have aged out, then — only if the
// backlog is still over the cap — the oldest unreported ones, loudly.
func (s *hookRelayUsageSink) pruneLocked(minute time.Time) {
	cutoff := minute.Add(-relayUsageBucketTTL).Unix()
	for k, v := range s.buckets {
		if !v.dirty && k.minute < cutoff {
			delete(s.buckets, k)
		}
	}
	if len(s.buckets) <= relayUsageMaxBuckets {
		return
	}
	keys, _ := s.pendingLocked() // oldest first
	drop := len(s.buckets) - relayUsageMaxBuckets
	if drop > len(keys) {
		drop = len(keys)
	}
	for _, k := range keys[:drop] {
		delete(s.buckets, k)
	}
	// Error, not Warn: this is unbilled traffic being discarded, and the only
	// way it happens is that reporting has been broken long enough to fill the
	// backlog — most likely a coordinator deployed ahead of its metering-svc.
	s.logger.Error("coord: relay usage backlog full; DISCARDING the oldest unreported buckets",
		"discarded", drop, "cap", relayUsageMaxBuckets,
		"hint", "is metering-svc older than this coordinator (no BillingHooks.ReportRelayUsage)?")
}
