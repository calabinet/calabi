package main

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
	pb "github.com/calabi/calabi/pkg/hooks-proto/hookspb"
)

// stubBilling stands in for metering-svc's BillingHooks. It records the samples
// of every accepted report, flattened, plus how many CALLS carried them — the
// two are different questions now that a round batches its whole backlog.
type stubBilling struct {
	pb.BillingHooksClient
	mu       sync.Mutex
	reported []*pb.RelayUsageSample
	calls    int
	fail     error
}

func (b *stubBilling) ReportRelayUsage(_ context.Context, in *pb.ReportRelayUsageRequest,
	_ ...grpc.CallOption) (*pb.ReportRelayUsageResponse, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fail != nil {
		return nil, b.fail
	}
	b.calls++
	b.reported = append(b.reported, in.GetSamples()...)
	return &pb.ReportRelayUsageResponse{}, nil
}

func (b *stubBilling) sent() []*pb.RelayUsageSample {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]*pb.RelayUsageSample(nil), b.reported...)
}

func (b *stubBilling) setFail(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.fail = err
}

func sinkWith(cli *stubBilling, now func() time.Time) *hookRelayUsageSink {
	return &hookRelayUsageSink{
		cli:     cli,
		logger:  slog.New(slog.DiscardHandler),
		now:     now,
		buckets: map[relayBucketKey]*relayBucketVal{},
	}
}

// Each report carries the minute's RUNNING TOTAL, not the delta that produced
// it. Metering merges duplicates by keeping the larger value, so a delta would
// be silently dropped on redelivery and two deltas in one minute would lose the
// smaller.
func TestSinkReportsTheRunningTotalForTheMinute(t *testing.T) {
	cli := &stubBilling{}
	at := time.Date(2026, 8, 23, 10, 0, 30, 0, time.UTC)
	s := sinkWith(cli, func() time.Time { return at })
	ctx := context.Background()

	rec := []core.RelayUsageRecord{{Meshnet: 7, Region: "lax", BytesIn: 100, BytesOut: 10}}
	_ = s.RecordRelayUsage(ctx, rec)
	at = at.Add(15 * time.Second) // still the same minute
	_ = s.RecordRelayUsage(ctx, rec)

	sent := cli.sent()
	if len(sent) != 2 {
		t.Fatalf("reported %d samples, want 2", len(sent))
	}
	if sent[0].GetBytesIn() != 100 || sent[1].GetBytesIn() != 200 {
		t.Fatalf("totals = %d then %d, want 100 then 200", sent[0].GetBytesIn(), sent[1].GetBytesIn())
	}
	if sent[0].GetTs() != sent[1].GetTs() {
		t.Error("two reports in the same minute landed in different buckets")
	}
	if sent[0].GetOrgId() != 7 || sent[0].GetRegion() != "lax" {
		t.Errorf("unexpected attribution: %+v", sent[0])
	}
}

// THE property. The relay's counters were reset when they were read, so these
// bytes exist nowhere else. A failed report must leave the bucket dirty and the
// next round must re-send the (now larger) total — merging by max makes the late
// arrival a correction, not a duplicate.
func TestSinkResendsAfterAFailedReport(t *testing.T) {
	cli := &stubBilling{fail: errors.New("metering is down")}
	at := time.Date(2026, 8, 23, 10, 0, 30, 0, time.UTC)
	s := sinkWith(cli, func() time.Time { return at })
	ctx := context.Background()

	_ = s.RecordRelayUsage(ctx, []core.RelayUsageRecord{{Meshnet: 7, Region: "lax", BytesIn: 100}})
	if len(cli.sent()) != 0 {
		t.Fatal("a failing metering recorded a sample")
	}

	cli.setFail(nil)
	at = at.Add(15 * time.Second)
	_ = s.RecordRelayUsage(ctx, []core.RelayUsageRecord{{Meshnet: 7, Region: "lax", BytesIn: 5}})

	sent := cli.sent()
	if len(sent) != 1 {
		t.Fatalf("reported %d samples, want 1", len(sent))
	}
	if sent[0].GetBytesIn() != 105 {
		t.Fatalf("bytes lost across the outage: got %d, want 105", sent[0].GetBytesIn())
	}
}

// A bucket that could not be reported still gets re-sent once its minute has
// passed — otherwise a blip at the wrong moment would strand a whole minute.
// Both buckets ride ONE call: a backlog is a batch, not a burst of round trips.
func TestSinkDrainsAnOlderDirtyBucket(t *testing.T) {
	cli := &stubBilling{fail: errors.New("metering is down")}
	at := time.Date(2026, 8, 23, 10, 0, 30, 0, time.UTC)
	s := sinkWith(cli, func() time.Time { return at })
	ctx := context.Background()

	_ = s.RecordRelayUsage(ctx, []core.RelayUsageRecord{{Meshnet: 7, Region: "lax", BytesIn: 100}})

	cli.setFail(nil)
	at = at.Add(2 * time.Minute) // a different bucket entirely
	_ = s.RecordRelayUsage(ctx, []core.RelayUsageRecord{{Meshnet: 7, Region: "lax", BytesIn: 5}})

	sent := cli.sent()
	if len(sent) != 2 {
		t.Fatalf("reported %d samples, want both the stranded bucket and the new one", len(sent))
	}
	if cli.calls != 1 {
		t.Errorf("the backlog took %d calls, want 1 — a batch, not a round trip per bucket", cli.calls)
	}
	// Oldest first, so a backlog drains in order.
	if sent[0].GetBytesIn() != 100 || sent[1].GetBytesIn() != 5 {
		t.Fatalf("got %d then %d, want 100 then 5", sent[0].GetBytesIn(), sent[1].GetBytesIn())
	}
	if sent[0].GetTs() >= sent[1].GetTs() {
		t.Error("the stranded bucket was not reported under its own minute")
	}
}

// The sink reports success even when metering is down, because from the moment
// it accepts a batch the buckets own those bytes. Telling the caller otherwise
// would make the poller retain a second copy and double-count it on the retry —
// each mechanism looks correct on its own, which is exactly why the ownership
// has to be stated.
func TestSinkNeverAsksTheCallerToRetain(t *testing.T) {
	cli := &stubBilling{fail: errors.New("metering is down")}
	at := time.Now().UTC()
	s := sinkWith(cli, func() time.Time { return at })

	if err := s.RecordRelayUsage(context.Background(),
		[]core.RelayUsageRecord{{Meshnet: 7, Region: "lax", BytesIn: 100}}); err != nil {
		t.Fatalf("sink returned an error the caller would act on: %v", err)
	}
}

// A cancelled poller context must not cancel the report in flight: these bytes
// exist nowhere else, so the call outlives the round that produced it.
func TestSinkReportsUnderACancelledContext(t *testing.T) {
	cli := &stubBilling{}
	at := time.Now().UTC()
	s := sinkWith(cli, func() time.Time { return at })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = s.RecordRelayUsage(ctx, []core.RelayUsageRecord{{Meshnet: 7, Region: "lax", BytesIn: 100}})

	if len(cli.sent()) != 1 {
		t.Fatal("a cancelled poller context took the usage report down with it")
	}
}

// Unreported buckets are never dropped on AGE — but they must be dropped on
// COUNT, or a coordinator deployed ahead of its metering-svc (ReportRelayUsage
// Unimplemented forever) grows a backlog until it dies, hours after the actual
// cause. Discarding the oldest unbilled bytes is the lesser loss.
func TestSinkBoundsTheUnreportedBacklog(t *testing.T) {
	cli := &stubBilling{fail: errors.New("unimplemented")}
	at := time.Date(2026, 8, 23, 10, 0, 30, 0, time.UTC)
	s := sinkWith(cli, func() time.Time { return at })
	ctx := context.Background()

	// One region per record keeps every bucket distinct within its minute.
	for i := 0; i < relayUsageMaxBuckets+50; i++ {
		at = at.Add(time.Minute)
		_ = s.RecordRelayUsage(ctx, []core.RelayUsageRecord{{Meshnet: 7, Region: "lax", BytesIn: 1}})
	}

	s.mu.Lock()
	n := len(s.buckets)
	s.mu.Unlock()
	if n > relayUsageMaxBuckets {
		t.Fatalf("backlog grew to %d buckets with the cap at %d — a permanently failing "+
			"report would take the coordinator down with it", n, relayUsageMaxBuckets)
	}
}
