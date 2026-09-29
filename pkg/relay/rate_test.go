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
	// forward() asks the DESTINATION's limiter, so B's must be in place before
	// the first frame — otherwise that frame goes out unmetered and the budget
	// is spent on the second.
	waitLimiter(t, h, keyB)

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
	type resolution struct {
		meshnet int64
		key     meshproto.NodeKey
	}
	// The resolver runs on each link's Serve goroutine, after add(), so
	// connectClient returning does not mean it has run yet. Collect the calls
	// over a channel and wait for them rather than share slices with the hub.
	// Buffered past the two expected calls so an extra one cannot block Serve.
	calls := make(chan resolution, 4)
	h := NewHub(slog.Default(), AuthConfig{}).
		WithRateLimiter(func(mn int64, k meshproto.NodeKey) RateLimiter {
			calls <- resolution{meshnet: mn, key: k}
			return nil // nil limiter = no limit, and must not panic on the hot path
		})

	connectClient(t, h, key(1))
	connectClient(t, h, key(2))

	perLink := map[meshproto.NodeKey]int{}
	for i := 0; i < 2; i++ {
		select {
		case r := <-calls:
			if r.meshnet != 0 {
				t.Fatalf("link %s: auth is off so the meshnet must be 0, got %d", r.key, r.meshnet)
			}
			perLink[r.key]++
		case <-time.After(2 * time.Second):
			t.Fatalf("resolver must run once per link, got %d call(s)", i)
		}
	}
	select {
	case r := <-calls:
		t.Fatalf("resolver must run once per link, got an extra call for %s", r.key)
	default:
	}
	if perLink[key(1)] != 1 || perLink[key(2)] != 1 {
		t.Fatalf("resolver must run once per link, got %v", perLink)
	}
}

// waitLimiter blocks until Serve has installed k's rate limiter. connectClient
// only waits for add(), and Serve resolves the limiter AFTER add() — outside
// the hub lock, on purpose (hub.go) — so a link can be Connected with no
// limiter yet. Frames reaching it in that window are forwarded unmetered,
// which production accepts and a test that counts refusals cannot.
func waitLimiter(t *testing.T, h *Hub, k meshproto.NodeKey) {
	t.Helper()
	eventually(t, func() bool {
		c := h.lookup(k)
		return c != nil && c.limiter.Load() != nil
	}, "the link's rate limiter was never installed")
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
