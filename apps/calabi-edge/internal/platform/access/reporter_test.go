package access

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"testing"
	"time"

	eventbus "github.com/calabinet/calabi/apps/calabi-edge/internal/bus"
)

type capturingBus struct {
	mu       sync.Mutex
	messages [][]byte
	err      error
}

func (b *capturingBus) Publish(_ string, payload []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return b.err
	}
	cp := make([]byte, len(payload))
	copy(cp, payload)
	b.messages = append(b.messages, cp)
	return nil
}

func (b *capturingBus) Subscribe(string, func(*eventbus.Msg)) (eventbus.Subscription, error) {
	return nil, nil
}

func (b *capturingBus) QueueSubscribe(string, string, func(*eventbus.Msg)) (eventbus.Subscription, error) {
	return nil, nil
}

func (b *capturingBus) Close() error { return nil }

func (b *capturingBus) reports(t *testing.T) []Report {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Report, 0, len(b.messages))
	for _, m := range b.messages {
		var rep Report
		if err := json.Unmarshal(m, &rep); err != nil {
			t.Fatalf("unmarshal published report: %v", err)
		}
		out = append(out, rep)
	}
	return out
}

func TestFlushPublishesAndStampsTheEdge(t *testing.T) {
	rec := New()
	rec.Note(7, 42, "203.0.113.5", Allowed, at(10))
	rec.Note(7, 42, "203.0.113.5", Allowed, at(10))
	bus := &capturingBus{}
	r := NewReporter(slog.Default(), bus, rec, 1000300003, "sgp-1", time.Minute)

	r.flush()

	reps := bus.reports(t)
	if len(reps) != 1 {
		t.Fatalf("published %d messages, want 1", len(reps))
	}
	if reps[0].EdgeNodeID != 1000300003 || reps[0].NodeLabel != "sgp-1" {
		t.Fatalf("edge identity not stamped: %+v", reps[0])
	}
	if len(reps[0].Rows) != 1 || reps[0].Rows[0].Conns != 2 {
		t.Fatalf("rows = %+v, want one row of 2", reps[0].Rows)
	}
}

// Nothing happened, nothing is published. An empty heartbeat every minute per
// edge is pure cost, and it would also make an idle edge indistinguishable
// from a busy one in the consumer's logs.
func TestFlushPublishesNothingWhenIdle(t *testing.T) {
	bus := &capturingBus{}
	r := NewReporter(slog.Default(), bus, New(), 1, "e", time.Minute)
	r.flush()
	if n := len(bus.reports(t)); n != 0 {
		t.Fatalf("published %d messages while idle, want 0", n)
	}
}

// A flush must not build one enormous message out of a whole MaxRows drain.
func TestFlushSplitsLargeDrains(t *testing.T) {
	rec := New()
	// Spread across tunnels so the per-tunnel visitor cap does not fold these
	// into overflow — this test is about message size, not the cap.
	want := 0
	for tunnel := int64(1); tunnel <= 8; tunnel++ {
		for i := 0; i < 200; i++ {
			rec.Note(7, tunnel, "203.0.113."+itoa(i), Allowed, at(10))
			want++
		}
	}
	bus := &capturingBus{}
	NewReporter(slog.Default(), bus, rec, 1, "e", time.Minute).flush()

	reps := bus.reports(t)
	if len(reps) < 2 {
		t.Fatalf("1600 rows went out in %d message(s); they must be split", len(reps))
	}
	total := 0
	for _, rep := range reps {
		if len(rep.Rows) > maxRowsPerMessage {
			t.Fatalf("a message carried %d rows, over the %d cap", len(rep.Rows), maxRowsPerMessage)
		}
		total += len(rep.Rows)
	}
	if total != want {
		t.Fatalf("split lost rows: published %d, drained %d", total, want)
	}
}

// Shutdown flushes. A graceful restart is the ordinary way an edge stops, and
// silently dropping the last interval every time would put a regular,
// predictable hole in the trail.
func TestRunFlushesOnShutdown(t *testing.T) {
	rec := New()
	rec.Note(7, 42, "203.0.113.5", Allowed, at(10))
	bus := &capturingBus{}
	// An interval far longer than the test: the only flush that can happen is
	// the one on the way out.
	r := NewReporter(slog.Default(), bus, rec, 1, "e", time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}

	if n := len(bus.reports(t)); n != 1 {
		t.Fatalf("shutdown published %d messages, want 1 — the last interval was dropped", n)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
