package relay

import (
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// budgetLimiter allows a fixed number of bytes and refuses everything after.
// Deliberately trivial: the real token bucket is the edge's business, and what
// the relay must get right is "ask, then honour the answer".
type budgetLimiter struct {
	left  atomic.Int64
	calls atomic.Int64
}

func (b *budgetLimiter) Allow(n int) bool {
	b.calls.Add(1)
	for {
		cur := b.left.Load()
		if cur < int64(n) {
			return false
		}
		if b.left.CompareAndSwap(cur, cur-int64(n)) {
			return true
		}
	}
}

// A refused frame must be dropped AND must not be billed. Usage is the org's
// invoice: charging for bytes the relay itself decided not to send would turn
// a rate limit into a way to run up someone's bill.
func TestRateLimiter_RefusedFrameIsDroppedAndNotBilled(t *testing.T) {
	const payload = 32 // bytes of "ciphertext" per frame below
	lim := &budgetLimiter{}
	lim.left.Store(payload) // exactly one frame's worth

	h := NewHub(slog.Default(), AuthConfig{}).
		WithRateLimiter(func(int64, meshproto.NodeKey) RateLimiter { return lim })
	keyA, keyB := key(1), key(2)
	connA := connectClient(t, h, keyA)
	connB := connectClient(t, h, keyB)

	cipher := make([]byte, payload)
	received := make(chan []byte, 2)
	go func() {
		for {
			typ, p, err := meshproto.ReadDERPFrame(connB)
			if err != nil {
				return
			}
			if typ != meshproto.DERPFrameRecvPacket {
				continue
			}
			_, c, err := meshproto.SplitPacket(p)
			if err != nil {
				return
			}
			received <- c
		}
	}()

	for i := 0; i < 2; i++ {
		if err := meshproto.WriteDERPFrame(connA, meshproto.DERPFrameSendPacket,
			meshproto.EncodePacket(keyB, cipher)); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}

	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("the first frame was within budget and must have been forwarded")
	}
	select {
	case <-received:
		t.Fatal("the second frame was over budget and must have been dropped")
	case <-time.After(300 * time.Millisecond):
	}

	if got := h.RefusedFrames(); got != 1 {
		t.Fatalf("RefusedFrames = %d, want 1", got)
	}
	// Billing: only the delivered frame's bytes may appear.
	var out uint64
	for _, d := range h.TakeUsage() {
		out += d.BytesOut
	}
	if out != payload {
		t.Fatalf("billed %d bytes, want %d — a refused frame must cost the org nothing", out, payload)
	}
}

// No resolver wired = every existing deployment, including every self-hosted
// relay. It must forward exactly as it did before rate limiting existed, and
// must not pay for an atomic per frame beyond the nil check.
func TestRateLimiter_UnwiredHubIsUnchanged(t *testing.T) {
	h := NewHub(slog.Default(), AuthConfig{})
	keyA, keyB := key(1), key(2)
	connA := connectClient(t, h, keyA)
	connB := connectClient(t, h, keyB)

	got := make(chan struct{}, 1)
	go func() {
		if _, _, err := meshproto.ReadDERPFrame(connB); err == nil {
			got <- struct{}{}
		}
	}()
	if err := meshproto.WriteDERPFrame(connA, meshproto.DERPFrameSendPacket,
		meshproto.EncodePacket(keyB, []byte("hello"))); err != nil {
		t.Fatalf("send: %v", err)
	}
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("a hub with no rate limiter must forward everything")
	}
	if h.RefusedFrames() != 0 {
		t.Fatal("nothing may be refused when no limiter is wired")
	}
}

// The limiter is chosen by MESHNET — that is the whole point of resolving it
// after the grant rather than at accept time. With auth off the meshnet is 0,
// and the resolver still gets called so a single-tenant operator can rate-limit
// a relay that issues no grants at all.
func TestRateLimiter_ResolvedPerLinkWithItsMeshnet(t *testing.T) {
	var seen []meshproto.NodeKey
	var meshnets []int64
	h := NewHub(slog.Default(), AuthConfig{}).
		WithRateLimiter(func(mn int64, k meshproto.NodeKey) RateLimiter {
			seen = append(seen, k)
			meshnets = append(meshnets, mn)
			return nil // nil limiter = no limit, and must not panic on the hot path
		})

	connectClient(t, h, key(1))
	connectClient(t, h, key(2))

	if len(seen) != 2 {
		t.Fatalf("resolver must run once per link, got %d", len(seen))
	}
	for i, mn := range meshnets {
		if mn != 0 {
			t.Fatalf("link %d: auth is off so the meshnet must be 0, got %d", i, mn)
		}
	}
}

// A nil limiter from the resolver, and a nil box, both mean "no limit". This is
// the path a relay takes for links the operator chose not to limit, and it runs
// per frame — it must not panic.
func TestRateLimiter_NilIsNoLimit(t *testing.T) {
	c := &client{}
	if !c.allow(1024) {
		t.Fatal("a link with no limiter must allow")
	}
	c.limiter.Store(&limiterBox{l: nil})
	if !c.allow(1024) {
		t.Fatal("a box holding nil must allow")
	}
}
