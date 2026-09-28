// usage_settle_test.go — the proxy-close hook has to hand the closing proxy's
// last bytes to the usage reporter.
//
// The reporter's own tests prove it can settle a closed proxy. They prove
// nothing about whether anyone CALLS it, and that is the half that was missing:
// the reporter only ever walked live sessions, so a tunnel that opened and
// closed between two ticks reported not one byte and then sat in the console as
// an offline tunnel with no traffic. This test drives the real hook.
//
// RUN: go test ./apps/calabi-edge/cmd/calabi-edge/ -run TestProxyClose -v
package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	eventbus "github.com/calabinet/calabi/apps/calabi-edge/internal/bus"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/platform/tunnelstore"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/platform/usage"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/router"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/session"
)

type settleBus struct {
	mu        sync.Mutex
	published [][]byte
}

func (b *settleBus) Publish(_ string, payload []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.published = append(b.published, append([]byte(nil), payload...))
	return nil
}
func (b *settleBus) Subscribe(string, func(*eventbus.Msg)) (eventbus.Subscription, error) {
	return settleSub{}, nil
}
func (b *settleBus) QueueSubscribe(string, string, func(*eventbus.Msg)) (eventbus.Subscription, error) {
	return settleSub{}, nil
}
func (b *settleBus) Close() error { return nil }

type settleSub struct{}

func (settleSub) Drain() error { return nil }

// reportsFor waits for the reporter's next tick to publish, and returns the
// totals it saw for one tunnel id. Polls rather than sleeps a fixed time: the
// bytes are already in the reporter before Run starts, so the first tick carries
// them and the loop normally exits on the first look.
func (b *settleBus) reportsFor(t *testing.T, tunnelID int64) (in, out uint64, seen bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		b.mu.Lock()
		for _, raw := range b.published {
			var rep usage.Report
			if json.Unmarshal(raw, &rep) != nil || rep.TunnelID != tunnelID {
				continue
			}
			in, out, seen = rep.BytesIn, rep.BytesOut, true
		}
		b.mu.Unlock()
		if seen {
			return in, out, true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return 0, 0, false
}

func settleFixture(t *testing.T) (*tunnelPersisterAdapter, *session.Session, *settleBus, *portBoundRPC) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := session.NewManager(log, nil)
	s := &session.Session{ID: "s1", TenantID: "42"}
	mgr.Register(s)

	bus := &settleBus{}
	rep := usage.NewReporter(log, bus, mgr, testEdgeID, "edge-a", 2*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = rep.Run(ctx) }()

	rpc := &portBoundRPC{}
	return &tunnelPersisterAdapter{
		tc:        tunnelstore.Wrap(log, rpc, testEdgeID, "edge-a", "cn-a.calabi.net"),
		logger:    log,
		edgeLabel: "edge-a",
		index:     &tunnelIDIndex{},
		ports:     router.NewPortPool(20000, 20999),
		usage:     rep,
	}, s, bus, rpc
}

func TestProxyCloseSettlesUsageForATunnelThatNeverSawATick(t *testing.T) {
	a, s, bus, rpc := settleFixture(t)

	// Opened, moved 4 KiB in / 8 KiB out, closed — the reporter never saw it
	// live, so this hook is the only place those counters can still be read.
	p := &session.Proxy{ID: "p1", TunnelID: 555}
	p.BytesIn.Store(4096)
	p.BytesOut.Store(8192)
	a.OnProxyClosed(s, p, "client_close")

	in, out, seen := bus.reportsFor(t, 555)
	if !seen {
		t.Fatal("the closed tunnel's bytes never reached the bus")
	}
	if in != 4096 || out != 8192 {
		t.Errorf("reported in=%d out=%d, want 4096/8192", in, out)
	}
	// And the hook's original job still happens.
	if len(rpc.statuses) != 1 || rpc.statuses[0].id != 555 || rpc.statuses[0].status != "offline" {
		t.Errorf("the row was not marked offline: %+v", rpc.statuses)
	}
}

// The hook returns early for a proxy with no tunnel row. Its bytes still belong
// to the org, and the unattributed bucket (tunnel_id 0) is what keeps the org
// total whole — so the settle has to happen BEFORE that return.
func TestProxyCloseSettlesUnattributedBytesToo(t *testing.T) {
	a, s, bus, rpc := settleFixture(t)

	p := &session.Proxy{ID: "p1"} // TunnelID 0: never persisted
	p.BytesIn.Store(1234)
	a.OnProxyClosed(s, p, "session_end")

	in, _, seen := bus.reportsFor(t, 0)
	if !seen {
		t.Fatal("unattributed bytes were dropped on close")
	}
	if in != 1234 {
		t.Errorf("reported in=%d, want 1234", in)
	}
	if len(rpc.statuses) != 0 {
		t.Errorf("a proxy with no row should report no status: %+v", rpc.statuses)
	}
}
