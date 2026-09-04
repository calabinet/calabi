package usage

import (
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	eventbus "github.com/calabi/calabi/apps/calabi-edge/internal/bus"
	"github.com/calabi/calabi/apps/calabi-edge/internal/session"
)

// fakeBus is a tiny in-memory eventbus.Bus stand-in. Publish records;
// Subscribe stores the handler so the test can drive it directly.
type fakeBus struct {
	mu          sync.Mutex
	published   []record
	subHandlers map[string]func(*eventbus.Msg)
}

type record struct {
	subject string
	data    []byte
}

func newFakeBus() *fakeBus {
	return &fakeBus{subHandlers: map[string]func(*eventbus.Msg){}}
}

func (b *fakeBus) Publish(subject string, payload []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.published = append(b.published, record{subject, append([]byte(nil), payload...)})
	return nil
}

func (b *fakeBus) Subscribe(subject string, h func(*eventbus.Msg)) (eventbus.Subscription, error) {
	b.mu.Lock()
	b.subHandlers[subject] = h
	b.mu.Unlock()
	return &fakeSub{}, nil
}

// QueueSubscribe in this fake delegates to Subscribe; this package's
// tests don't exercise queue-group semantics. bridge_test.go has its
// own queue-aware fake.
func (b *fakeBus) QueueSubscribe(subject, _ string, h func(*eventbus.Msg)) (eventbus.Subscription, error) {
	return b.Subscribe(subject, h)
}

func (b *fakeBus) Close() error { return nil }

// Drive the deny subscriber as if NATS delivered a message.
func (b *fakeBus) DeliverDeny(subject string, payload []byte) {
	b.mu.Lock()
	// pattern-match on the >  wildcard subscription
	var h func(*eventbus.Msg)
	for sub, handler := range b.subHandlers {
		if matchesWildcard(sub, subject) {
			h = handler
			break
		}
	}
	b.mu.Unlock()
	if h != nil {
		h(&eventbus.Msg{Subject: subject, Data: payload})
	}
}

func matchesWildcard(pattern, subject string) bool {
	// "calabi.usage.deny.>" matches any subject starting with
	// "calabi.usage.deny.".
	if len(pattern) >= 1 && pattern[len(pattern)-1] == '>' {
		prefix := pattern[:len(pattern)-1]
		return len(subject) >= len(prefix) && subject[:len(prefix)] == prefix
	}
	return pattern == subject
}

type fakeSub struct{}

func (fakeSub) Drain() error { return nil }

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
}

// ----- Reporter -----

func TestReporter_PublishesPerOrgDeltas(t *testing.T) {
	mgr := session.NewManager(quietLogger(), nil)

	// Two sessions for org=42, one for org=7. These write the
	// session-level fallback counter (no proxies registered), which the
	// reporter publishes under tunnel_id=0 — exercising the unattributed
	// bucket and confirming org totals still aggregate correctly.
	s1 := &session.Session{ID: "s1", TenantID: "42"}
	s2 := &session.Session{ID: "s2", TenantID: "42"}
	s3 := &session.Session{ID: "s3", TenantID: "7"}
	mgr.Register(s1)
	mgr.Register(s2)
	mgr.Register(s3)
	s1.BytesIn.Store(1000)
	s2.BytesIn.Store(500)
	s2.BytesOut.Store(200)
	s3.BytesIn.Store(50)

	bus := newFakeBus()
	r := NewReporter(quietLogger(), bus, mgr, 201, "edge-1", time.Millisecond)
	r.tick()

	// Verify one Report per org with the correct totals.
	bus.mu.Lock()
	defer bus.mu.Unlock()
	if len(bus.published) != 2 {
		t.Fatalf("want 2 reports, got %d: %+v", len(bus.published), bus.published)
	}
	type tot struct{ in, out uint64 }
	got := map[int64]tot{}
	for _, p := range bus.published {
		if p.subject != SubjectReport {
			t.Errorf("unexpected subject %q", p.subject)
		}
		var rep Report
		_ = json.Unmarshal(p.data, &rep)
		if rep.TunnelID != 0 {
			t.Errorf("session-level counters should report tunnel_id=0, got %d", rep.TunnelID)
		}
		got[rep.OrgID] = tot{rep.BytesIn, rep.BytesOut}
	}
	if got[42] != (tot{1500, 200}) {
		t.Errorf("org=42 want in=1500 out=200, got %+v", got[42])
	}
	if got[7] != (tot{50, 0}) {
		t.Errorf("org=7 want in=50 out=0, got %+v", got[7])
	}
}

// TestReporter_PublishesPerTunnelDeltas verifies that bytes accumulated on
// per-proxy counters are reported broken down by tunnel_id.
func TestReporter_PublishesPerTunnelDeltas(t *testing.T) {
	mgr := session.NewManager(quietLogger(), nil)
	s := &session.Session{ID: "s1", TenantID: "42"}
	mgr.Register(s)

	p1 := &session.Proxy{ID: "p1", TunnelID: 100}
	p2 := &session.Proxy{ID: "p2", TunnelID: 200}
	s.RegisterProxy(p1)
	s.RegisterProxy(p2)
	p1.BytesIn.Store(1000)
	p1.BytesOut.Store(10)
	p2.BytesIn.Store(500)

	bus := newFakeBus()
	r := NewReporter(quietLogger(), bus, mgr, 201, "edge-1", time.Millisecond)
	r.tick()

	bus.mu.Lock()
	defer bus.mu.Unlock()
	if len(bus.published) != 2 {
		t.Fatalf("want 2 per-tunnel reports, got %d: %+v", len(bus.published), bus.published)
	}
	type tot struct{ in, out uint64 }
	got := map[int64]tot{}
	for _, p := range bus.published {
		var rep Report
		_ = json.Unmarshal(p.data, &rep)
		if rep.OrgID != 42 {
			t.Errorf("want org=42, got %d", rep.OrgID)
		}
		got[rep.TunnelID] = tot{rep.BytesIn, rep.BytesOut}
	}
	if got[100] != (tot{1000, 10}) {
		t.Errorf("tunnel=100 want in=1000 out=10, got %+v", got[100])
	}
	if got[200] != (tot{500, 0}) {
		t.Errorf("tunnel=200 want in=500 out=0, got %+v", got[200])
	}
}

// TestReporter_ProxyDeltaOnly verifies a per-proxy counter reports the
// delta since the last tick, not the cumulative total.
func TestReporter_ProxyDeltaOnly(t *testing.T) {
	mgr := session.NewManager(quietLogger(), nil)
	s := &session.Session{ID: "s1", TenantID: "10"}
	mgr.Register(s)
	p := &session.Proxy{ID: "p1", TunnelID: 7}
	s.RegisterProxy(p)
	p.BytesIn.Store(100)

	bus := newFakeBus()
	r := NewReporter(quietLogger(), bus, mgr, 201, "edge-1", time.Millisecond)
	r.tick() // publishes 100 in for tunnel 7

	bus.mu.Lock()
	first := len(bus.published)
	bus.mu.Unlock()
	r.tick() // idle → no new publish
	bus.mu.Lock()
	if len(bus.published) != first {
		t.Fatalf("idle tick still published: %d vs %d", len(bus.published), first)
	}
	bus.mu.Unlock()

	p.BytesIn.Store(350)
	r.tick()
	bus.mu.Lock()
	defer bus.mu.Unlock()
	last := bus.published[len(bus.published)-1]
	var rep Report
	_ = json.Unmarshal(last.data, &rep)
	if rep.TunnelID != 7 {
		t.Fatalf("want tunnel=7, got %d", rep.TunnelID)
	}
	if rep.BytesIn != 250 {
		t.Fatalf("want delta=250, got %d", rep.BytesIn)
	}
}

func TestReporter_DeltaOnly_NotCumulative(t *testing.T) {
	mgr := session.NewManager(quietLogger(), nil)
	s := &session.Session{ID: "s1", TenantID: "10"}
	mgr.Register(s)
	s.BytesIn.Store(100)

	bus := newFakeBus()
	r := NewReporter(quietLogger(), bus, mgr, 201, "edge-1", time.Millisecond)
	r.tick() // publishes 100 in

	// No new activity → no message on second tick.
	bus.mu.Lock()
	first := len(bus.published)
	bus.mu.Unlock()
	r.tick()
	bus.mu.Lock()
	if len(bus.published) != first {
		t.Fatalf("idle tick still published: %d vs %d", len(bus.published), first)
	}
	bus.mu.Unlock()

	// New activity → delta only.
	s.BytesIn.Store(350)
	r.tick()
	bus.mu.Lock()
	defer bus.mu.Unlock()
	last := bus.published[len(bus.published)-1]
	var rep Report
	_ = json.Unmarshal(last.data, &rep)
	if rep.BytesIn != 250 {
		t.Fatalf("want delta=250, got %d", rep.BytesIn)
	}
}

func TestReporter_SkipsNonNumericTenant(t *testing.T) {
	mgr := session.NewManager(quietLogger(), nil)
	s := &session.Session{ID: "s1", TenantID: "dev"} // not numeric
	mgr.Register(s)
	s.BytesIn.Store(999)

	bus := newFakeBus()
	r := NewReporter(quietLogger(), bus, mgr, 201, "edge-1", time.Millisecond)
	r.tick()

	bus.mu.Lock()
	defer bus.mu.Unlock()
	if len(bus.published) != 0 {
		t.Fatalf("non-numeric tenant should be skipped; got %d reports", len(bus.published))
	}
}

// ----- DenyHook -----

func TestDenyHook_BlocksAndAllows(t *testing.T) {
	bus := newFakeBus()
	h := NewDenyHook(quietLogger(), bus)
	if err := h.Start(); err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	// Initially unblocked.
	if blocked, _ := h.IsBlocked(42); blocked {
		t.Fatal("org=42 should not be blocked initially")
	}

	// Deliver a deny event.
	bus.DeliverDeny("calabi.usage.deny.42", []byte(`{"reason":"over_monthly_traffic_mb"}`))

	if blocked, reason := h.IsBlocked(42); !blocked {
		t.Fatal("org=42 should be blocked")
	} else if reason != "over_monthly_traffic_mb" {
		t.Fatalf("reason: %q", reason)
	}

	// Other orgs unaffected.
	if blocked, _ := h.IsBlocked(7); blocked {
		t.Fatal("org=7 should not be blocked")
	}

	// Allow lifts the block.
	h.Allow(42)
	if blocked, _ := h.IsBlocked(42); blocked {
		t.Fatal("org=42 should be unblocked after Allow")
	}
}

func TestDenyHook_NilBusGracefullyNoOp(t *testing.T) {
	h := NewDenyHook(quietLogger(), nil)
	if err := h.Start(); err != nil {
		t.Fatalf("Start with nil bus: %v", err)
	}
	if blocked, _ := h.IsBlocked(1); blocked {
		t.Fatal("nil-bus hook should never block")
	}
	_ = h.Close()
}

// Compile-time check that fakeBus satisfies eventbus.Bus.
var _ eventbus.Bus = (*fakeBus)(nil)

// Reference to silence "unused" complaints on minor symbols.
var _ = atomic.LoadInt64
