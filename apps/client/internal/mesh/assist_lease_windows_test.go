//go:build windows && assistintegration

package mesh

import (
	"context"
	"github.com/calabinet/calabi/apps/client/internal/assistance"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type leasePath struct{ bytes, packets, dropped atomic.Int64 }

const leaseReturnRate = 2_000_000

func (l *leasePath) pipe(ctx context.Context, out chan []byte, cut *atomic.Bool, from int) chan []byte {
	in := make(chan []byte)
	type slot struct {
		p    []byte
		due  time.Time
		drop bool
	}
	q := make(chan slot, 512)
	go func() {
		var tail time.Time
		for {
			select {
			case <-ctx.Done():
				return
			case p := <-in:
				now := time.Now()
				if tail.Before(now) {
					tail = now
				}
				n := l.packets.Add(1)
				if tail.Sub(now) > 90*time.Millisecond {
					l.dropped.Add(1)
					continue
				}
				rate := leaseReturnRate
				if from == 0 {
					rate = 4_000_000
				}
				tail = tail.Add(time.Duration(len(p)) * 8 * time.Second / time.Duration(rate))
				select {
				case q <- slot{p, tail.Add(30 * time.Millisecond), n%200 == 111}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case s := <-q:
				if wait := time.Until(s.due); wait > 0 {
					time.Sleep(wait)
				}
				if cut.Load() {
					continue
				}
				l.bytes.Add(int64(len(s.p)))
				if s.drop {
					l.dropped.Add(1)
					continue
				}
				select {
				case out <- s.p:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return in
}

func testWeakLease(t *testing.T, route string, note assistNote, client *http.Client, target netip.Addr, port uint16, cut *atomic.Bool, shape *[2]leasePath) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var controller assistance.Controller
	var id string
	epoch := 0
	call := func(op, input string, x, y int) assistance.Reply {
		t.Helper()
		r, e := controller.Do(ctx, client, target, port, assistance.Command{ID: id, Op: op, Epoch: epoch, Input: input, X: x, Y: y})
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	id = call("request", "", 0, 0).ID
	t.Log("等待现场同意查看和允许控制")
	awaitControl := func() {
		t.Helper()
		for {
			r := call("frame", "", 0, 0)
			if r.State == "control" {
				epoch = r.Epoch
				return
			}
			if ctx.Err() != nil {
				t.Fatal(ctx.Err())
			}
			time.Sleep(60 * time.Millisecond)
		}
	}
	awaitControl()
	x, y := note.point(t)
	input := func(kind string, x, y int) {
		t.Helper()
		if !call("input", kind, x, y).Applied {
			t.Fatal("input refused", kind)
		}
	}
	input("down", x, y)
	input("move", x+1150, y)
	input("keydown", 16, 0)
	if !heldAssist(16) || !heldAssist(1) {
		t.Fatal("hold failed")
	}
	// Concurrent preview reads saturate the return path without possessing the input epoch.
	load, stop := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() { stop(); wg.Wait() }()
	var frames atomic.Int64
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for load.Err() == nil {
				r, e := assistance.Exchange(load, client, target, port, assistance.Command{ID: id, Op: "frame"})
				if e == nil && len(r.Frame) > 0 {
					frames.Add(1)
				}
			}
		}()
	}
	start := time.Now()
	bytes := shape[1].bytes.Load()
	drops := shape[1].dropped.Load()
	moves := 0
	for time.Since(start) < 8*time.Second {
		dx := 850 + 300*(moves%2)
		input("move", x+dx, y)
		moves++
		if moves == 4 {
			if frame := call("frame", "", 0, 0); frame.State != "control" || len(frame.Frame) == 0 {
				t.Fatal("control lost during contended preview")
			}
		}
		sel, _, _ := assistUser.NewProc("SendMessageW").Call(note.edit, 0xb0, 0, 0)
		if sel>>16&65535 == sel&65535 || !heldAssist(16) || !heldAssist(1) {
			t.Fatalf("lost active drag under load, move=%d sel=%x shift=%t left=%t", moves, sel, heldAssist(16), heldAssist(1))
		}
	}
	used := 100 * float64(shape[1].bytes.Load()-bytes) * 8 / (time.Since(start).Seconds() * leaseReturnRate)
	losses := shape[1].dropped.Load() - drops
	t.Logf("%s: return utilization %.1f%%, drops %d, frames %d, moves %d", route, used, losses, frames.Load(), moves)
	if used < 90 || losses == 0 || frames.Load() == 0 || moves < 2 {
		t.Fatal("insufficient weak load")
	}
	cutAt := time.Now()
	cut.Store(true)
	old := assistance.Command{ID: id, Epoch: epoch, Op: "input", Input: "keydown", X: 55}
	raw := func(c assistance.Command) (assistance.Reply, error) {
		return assistance.Exchange(ctx, client, target, port, c)
	}
	type delivery struct {
		reply assistance.Reply
		err   error
	}
	queued := make(chan delivery, 1)
	before := note.text()
	go func() { r, e := controller.Do(ctx, client, target, port, old); queued <- delivery{r, e} }()
	var shift, left time.Duration
	for time.Since(cutAt) < 1500*time.Millisecond {
		if shift == 0 && !heldAssist(16) {
			shift = time.Since(cutAt)
		}
		if left == 0 && !heldAssist(1) {
			left = time.Since(cutAt)
		}
		if shift > 0 && left > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	t.Logf("cut Shift=%v left=%v", shift, left)
	if shift <= 0 || left <= 0 || shift >= time.Second || left >= time.Second {
		t.Fatal("missed release deadline")
	}
	stop()
	wg.Wait()
	cut.Store(false)
	delivered := <-queued
	if delivered.err != nil || delivered.reply.State != "view" || delivered.reply.Applied {
		t.Fatal("queued key was not rejected by the recovered host", delivered.err, delivered.reply.State)
	}
	if r := call("frame", "", 0, 0); r.State != "view" || len(r.Frame) == 0 {
		t.Fatal("expected view-only recovery", r.State)
	}
	if r, err := raw(old); err != nil || r.Applied || note.text() != before {
		t.Fatal("old input on recovery")
	}
	t.Log("已恢复仅查看，请再次点击允许控制")
	awaitControl()
	if epoch == old.Epoch {
		t.Fatal("epoch reused")
	}
	input("down", x, y)
	input("up", 0, 0)
	if r, e := raw(old); e != nil || r.Applied || note.text() != before {
		t.Fatal("stale input under new epoch", e)
	}
	before = note.text()
	input("keydown", 55, 0)
	input("keyup", 55, 0)
	if len(note.text()) != len(before)+1 {
		t.Fatal("fresh grant input missing")
	}
	call("end", "", 0, 0)
}
