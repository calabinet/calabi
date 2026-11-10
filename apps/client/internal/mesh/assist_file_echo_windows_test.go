//go:build windows && assistintegration

package mesh

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/draw"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/calabinet/calabi/apps/client/internal/assistance"
	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Feed the production sender's OS socket into the isolated Windows-side netstack.
// TLS terminates only at the paired controller-side file receiver.
func echoFile(t *testing.T, ctx context.Context, p *probeBusinessPair, nets [2]*netstack.Net, viewer, desktop *filetransfer.Identity, offset *atomic.Int64) <-chan error {
	t.Helper()
	const size = 12 << 20
	allow := func() bool { return true }
	r, e := filetransfer.NewReceiver(filetransfer.ReceiverConfig{Peer: filetransfer.Peer{IP: p.addresses[1], Fingerprint: desktop.Fingerprint}, Directory: t.TempDir(), Kbps: 4096, MaxBytes: size, Allowed: allow, Durable: true, Scope: "echo-file"})
	if e != nil {
		t.Fatal(e)
	}
	ln, e := nets[0].ListenTCPAddrPort(netip.AddrPortFrom(p.addresses[0], 17402))
	if e != nil {
		t.Fatal(e)
	}
	srv, closed := r.Serve(ln, viewer)
	t.Cleanup(func() { srv.Close(); <-closed; r.Close() })
	proxy, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { proxy.Close() })
	go func() {
		for {
			c, e := proxy.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				d, e := nets[1].DialContext(ctx, "tcp", ln.Addr().String())
				if e != nil {
					return
				}
				defer d.Close()
				go func() { io.Copy(d, c); d.Close() }()
				io.Copy(c, d)
			}()
		}
	}()
	loop := netip.MustParseAddr("127.0.0.1")
	budget, _ := filetransfer.NewPacer(4096)
	sender, e := filetransfer.NewBatchSender(desktop, loop, filetransfer.Peer{IP: loop, Fingerprint: viewer.Fingerprint}, proxy.Addr().(*net.TCPAddr).Port, budget, allow, "echo-file")
	if e != nil {
		t.Fatal(e)
	}
	body := make([]byte, size)
	if _, e = rand.Read(body); e != nil {
		t.Fatal(e)
	}
	go func() {
		for ctx.Err() == nil {
			for _, f := range r.List() {
				if f.State == "waiting" {
					r.Decide(f.ID, true)
					return
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	done := make(chan error, 1)
	go func() {
		defer sender.Close()
		var ticket filetransfer.BatchTicket
		done <- sender.SendBatch(ctx, []filetransfer.Source{{Reader: bytes.NewReader(body), Size: size, Name: "isolated-echo.bin"}}, &ticket, func(filetransfer.BatchTicket) error { return nil }, func(v filetransfer.BatchProgress) {
			if v.Transfer.Offset > 0 {
				offset.Store(v.Transfer.Offset)
			}
		})
	}()
	return done
}

// Observe only acknowledgements of the production controller's own renewals.
type echoTraceEvent struct {
	ms int64
	op string
}
type echoPulseTrace struct {
	mu               sync.Mutex
	events           []echoTraceEvent
	tracing          bool
	hold             atomic.Bool
	holdDuration     time.Duration
	base             http.RoundTripper
	last, ok, failed atomic.Int64
}

func (tr *echoPulseTrace) mark(op string) {
	if tr.tracing {
		tr.mu.Lock()
		tr.events = append(tr.events, echoTraceEvent{time.Now().UnixMilli(), op})
		tr.mu.Unlock()
	}
}
func (tr *echoPulseTrace) RoundTrip(req *http.Request) (*http.Response, error) {
	var c assistance.Command
	if req.GetBody != nil {
		copy, err := req.GetBody()
		if err == nil {
			json.NewDecoder(copy).Decode(&c)
			copy.Close()
		}
	}
	tr.mark(c.Op + "_start")
	resp, err := tr.base.RoundTrip(req)
	if c.Op == "frame_delta" && err == nil && tr.hold.Swap(false) {
		// Delay delivery to the calling lane, not the actual mesh or the host.
		delay := tr.holdDuration
		if delay == 0 {
			delay = 2 * time.Second
		}
		time.Sleep(delay)
	}
	if c.Op != "pulse" {
		return resp, err
	}
	if err == nil && resp.StatusCode == 200 {
		data, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			tr.failed.Add(1)
			return nil, readErr
		}
		resp.Body = io.NopCloser(bytes.NewReader(data))
		var r assistance.Reply
		if json.Unmarshal(data, &r) == nil && r.State == "control" && r.Epoch == c.Epoch {
			tr.mark("pulse_ack")
			tr.ok.Add(1)
			tr.last.Store(time.Now().UnixMilli())
			return resp, nil
		}
	}
	tr.failed.Add(1)
	return resp, err
}

func testFileEcho(t *testing.T, note assistNote, client *http.Client, p *probeBusinessPair, nets [2]*netstack.Net, viewer, desktop *filetransfer.Identity, cut *atomic.Bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	diagnose := os.Getenv("CALABI_ASSIST_LEASE_DIAG") == "1"
	loadedLease := os.Getenv("CALABI_ASSIST_LOADED_LEASE") == "1"
	splitAB := os.Getenv("CALABI_ASSIST_SPLIT_AB") == "1"
	compare := splitAB || os.Getenv("CALABI_ASSIST_INPUT_AB") == "1"
	var observer *echoPulseTrace
	if compare || diagnose {
		tr := &echoPulseTrace{base: client.Transport, tracing: diagnose}
		observer = tr
		if diagnose {
			path := filepath.Join(t.TempDir(), "lease.log")
			t.Setenv("CALABI_ASSIST_TEST_LEASE_TRACE", path)
			defer func() {
				data, _ := os.ReadFile(path)
				tr.mu.Lock()
				defer tr.mu.Unlock()
				for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
					if line == "" {
						continue
					}
					var stamp int64
					fmt.Sscan(line, &stamp)
					t.Log("host", line)
					for _, e := range tr.events {
						if e.ms >= stamp-1900 && e.ms <= stamp+100 {
							t.Logf("wire %d %+dms %s", e.ms, e.ms-stamp, e.op)
						}
					}
				}
			}()
		}
		copied := *client
		copied.Transport = tr
		client = &copied
		defer func() {
			t.Logf("pulse_ack_unix_ms=%d age_at_exit_ms=%d ok=%d failed=%d", tr.last.Load(), time.Now().UnixMilli()-tr.last.Load(), tr.ok.Load(), tr.failed.Load())
		}()
	}
	var ctrl assistance.Controller
	defer ctrl.Suspend()
	dest := p.addresses[1]
	const port = 17401
	var id string
	var epoch, revision int
	call := func(c assistance.Command) assistance.Reply {
		t.Helper()
		c.ID = id
		c.Epoch = epoch
		r, e := ctrl.Do(ctx, client, dest, port, c)
		if e != nil {
			t.Fatal(e)
		}
		if epoch != 0 && (r.State != "control" || r.Epoch != epoch) {
			t.Fatalf("lost control state=%s epoch=%d", r.State, r.Epoch)
		}
		return r
	}
	id = call(assistance.Command{Op: "request", Input: "outcome-v1"}).ID
	defer func() {
		end, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		assistance.Exchange(end, client, dest, port, assistance.Command{Op: "end", ID: id})
	}()
	var canvas *image.RGBA
	applyFrame := func(r assistance.Reply) {
		t.Helper()
		if epoch == 0 && r.State == "control" {
			epoch = r.Epoch
		}
		revision = r.Revision
		payload := r.Frame
		if payload == "" {
			payload = r.Patch
		}
		if payload == "" {
			return
		}
		data, e := base64.StdEncoding.DecodeString(payload)
		if e != nil {
			t.Fatal(e)
		}
		im, _, e := image.Decode(bytes.NewReader(data))
		if e != nil {
			t.Fatal(e)
		}
		if r.Frame != "" {
			canvas = image.NewRGBA(im.Bounds())
		}
		draw.Draw(canvas, im.Bounds().Add(image.Pt(r.X, r.Y)), im, im.Bounds().Min, draw.Src)
	}
	paint := func() { applyFrame(call(assistance.Command{Op: "frame_delta", Baseline: revision})) }
	// A frame can update pixels only while its original control generation is current.
	// Control state itself belongs to the serialized input lane.
	acceptFrame := func(sentEpoch int, r assistance.Reply) bool {
		if epoch == 0 || epoch != sentEpoch || r.Epoch != epoch || r.State != "control" {
			return false
		}
		applyFrame(r)
		return true
	}
	t.Log("PENDING: click view then control")
	for epoch == 0 {
		r := call(assistance.Command{Op: "release"})
		switch r.State {
		case "control":
			epoch = r.Epoch
		case "pending", "view":
		default:
			t.Fatalf("authorization ended: %s", r.State)
		}
		time.Sleep(40 * time.Millisecond)
	}
	verify := os.Getenv("CALABI_ASSIST_FRAME_LEASE") == "1"
	cutOnly := verify && os.Getenv("CALABI_ASSIST_CUT_ONLY") == "1"
	if verify && !cutOnly {
		call(assistance.Command{Op: "release"})
		observer.hold.Store(true)
		finish := ctrl.TrackFrame(id, epoch)
		r, e := assistance.Exchange(ctx, client, dest, port, assistance.Command{Op: "frame_delta", ID: id, Epoch: epoch})
		finish(r, e)
		if e != nil || !acceptFrame(epoch, r) {
			t.Fatal("delayed frame rejected", e)
		}
		call(assistance.Command{Op: "release"})
		t.Log("2s independent frame retained control")
	}

	if diagnose && os.Getenv("CALABI_ASSIST_LEASE_PAIR") == "1" {
		// Both variants use the same permission, peer, transport and delay.
		for _, managed := range []bool{true, false} {
			call(assistance.Command{Op: "release"})
			c := assistance.Command{Op: "frame_delta", ID: id, Epoch: epoch, Baseline: revision}
			observer.hold.Store(true)
			var r assistance.Reply
			var err error
			if managed {
				r, err = ctrl.Do(ctx, client, dest, port, c)
			} else {
				r, err = assistance.Exchange(ctx, client, dest, port, c)
			}
			if err != nil {
				t.Fatal(err)
			}
			revision = r.Revision
			r, err = assistance.Exchange(ctx, client, dest, port, assistance.Command{Op: "release", ID: id, Epoch: epoch})
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("hold=2s managed=%t post_hold_state=%s", managed, r.State)
			if managed && r.State != "control" || !managed && r.State != "view" {
				t.Fatal("unexpected diagnostic state")
			}
		}
		return
	}

	var staleEpoch int
	if verify && !cutOnly || splitAB && !diagnose {
		// Hold a genuine authorized frame at the viewer delivery boundary.
		oldEpoch := epoch
		oldFinish := ctrl.TrackFrame(id, epoch)
		saved, frameErr := assistance.Exchange(ctx, client, dest, port, assistance.Command{Op: "frame", ID: id, Epoch: epoch})
		if frameErr != nil {
			t.Fatal(frameErr)
		}
		if saved.Frame == "" || saved.State != "control" {
			t.Fatal("no controlled frame to delay")
		}
		t.Log("REVOKE NOW: click revoke control")
		deadline := time.Now().Add(90 * time.Second)
		for {
			r, e := ctrl.Do(ctx, client, dest, port, assistance.Command{Op: "release", ID: id, Epoch: oldEpoch})
			if e != nil {
				t.Fatal(e)
			}
			if r.State == "view" {
				epoch = 0
				break
			}
			if r.State != "control" || time.Now().After(deadline) {
				t.Fatal("revoke not observed", r.State)
			}
			time.Sleep(100 * time.Millisecond)
		}
		if acceptFrame(oldEpoch, saved) || epoch != 0 {
			t.Fatal("late frame restored control")
		}
		before := note.text()
		r, e := assistance.Exchange(ctx, client, dest, port, assistance.Command{Op: "input", Input: "text", Text: "X", Seq: 1, ID: id, Epoch: oldEpoch})
		if e != nil || r.Applied || r.State != "view" || note.text() != before {
			t.Fatal("stale input accepted or state unavailable", e)
		}
		t.Log("late control frame ignored and stale input rejected")
		t.Log("REGRANT NOW: allow control again")
		for time.Now().Before(deadline.Add(90 * time.Second)) {
			r := call(assistance.Command{Op: "release"})
			if r.State == "control" && r.Epoch != oldEpoch {
				epoch = r.Epoch
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		oldFinish(saved, nil)
		staleEpoch = oldEpoch
		if epoch == 0 || acceptFrame(oldEpoch, saved) {
			t.Fatal("new grant did not isolate prior generation")
		}
	}

	x, y := note.point(t)
	input := func(kind string, x, y int) {
		t.Helper()
		if !call(assistance.Command{Op: "input", Input: kind, X: x, Y: y}).Applied {
			t.Fatalf("input refused: %s", kind)
		}
	}
	input("down", x, y)
	input("up", 0, 0)
	focus := func() {
		t.Helper()
		fg, _, _ := assistUser.NewProc("GetForegroundWindow").Call()
		if fg != note.hwnd {
			t.Fatal("fixture lost foreground")
		}
	}
	focus()
	if verify {
		before := note.text()
		r, e := assistance.Exchange(ctx, client, dest, port, assistance.Command{Op: "input", Input: "text", Text: "X", Seq: 1, ID: id, Epoch: staleEpoch})
		if e != nil || r.Applied || note.text() != before {
			t.Fatal("old epoch input after regrant", e)
		}
		input("keydown", 16, 0)
		input("down", x, y)
		input("move", x+1150, y)
		if !heldAssist(16) || !heldAssist(1) {
			t.Fatal("hold failed")
		}
		observer.hold.Store(true)
		cmd := assistance.Command{Op: "frame_delta", ID: id, Epoch: epoch, Baseline: revision}
		finish := ctrl.TrackFrame(id, epoch)
		done := make(chan struct{})
		go func() { r, e := assistance.Exchange(ctx, client, dest, port, cmd); finish(r, e); close(done) }()
		until := time.Now().Add(3 * time.Second)
		for observer.hold.Load() && time.Now().Before(until) {
			time.Sleep(time.Millisecond)
		}
		if observer.hold.Load() || !heldAssist(16) || !heldAssist(1) {
			t.Fatal("frame not held at cut")
		}
		start := time.Now()
		cut.Store(true)
		defer cut.Store(false)
		var shift, left time.Duration
		for time.Since(start) < time.Second && (shift == 0 || left == 0) {
			if shift == 0 && !heldAssist(16) {
				shift = time.Since(start)
			}
			if left == 0 && !heldAssist(1) {
				left = time.Since(start)
			}
			time.Sleep(time.Millisecond)
		}
		if shift == 0 || left == 0 || shift >= time.Second || left >= time.Second {
			t.Fatalf("release deadline shift=%v left=%v", shift, left)
		}
		cut.Store(false)
		t.Logf("observed OS release after cut: shift=%v left=%v", shift, left)
		r, e = assistance.Exchange(ctx, client, dest, port, assistance.Command{Op: "input", Input: "text", Text: "X", Seq: 1, ID: id, Epoch: epoch})
		if e != nil || r.Applied || r.State != "view" || note.text() != before {
			t.Fatal("could not verify view-only rejection after recovery", e, r.State)
		}
		<-done
		t.Logf("cut during tracked frame: shift=%v left=%v; stale input rejected after recovery", shift, left)
		return
	}

	sm := assistUser.NewProc("SendMessageW")
	reset := func(s string) {
		u, _ := windows.UTF16PtrFromString(s)
		sm.Call(note.edit, 0xc, 0, uintptr(unsafe.Pointer(u)))
		sm.Call(note.edit, 0xb1, 0, 0)
	}
	reset("7777 ")
	charPoint := func(i int) image.Point {
		pos, _, _ := sm.Call(note.edit, 0xd6, uintptr(i), 0)
		q := [2]int32{int32(int16(pos)), int32(int16(pos >> 16))}
		assistUser.NewProc("ClientToScreen").Call(note.edit, uintptr(unsafe.Pointer(&q)))
		w, _, _ := assistUser.NewProc("GetSystemMetrics").Call(0)
		h, _, _ := assistUser.NewProc("GetSystemMetrics").Call(1)
		return image.Pt(int(q[0])*canvas.Bounds().Dx()/int(w), int(q[1])*canvas.Bounds().Dy()/int(h))
	}
	paint()
	start, end := charPoint(3), charPoint(4)
	dark := func(q image.Point) bool { r, g, b, _ := canvas.At(q.X, q.Y).RGBA(); return (r+g+b)/3 < 33000 }
	var glyph []image.Point
	for xx := start.X + 1; xx < end.X; xx++ {
		for yy := start.Y; yy < start.Y+20; yy++ {
			pt := image.Pt(xx, yy)
			if dark(pt) {
				glyph = append(glyph, pt)
			}
		}
	}
	if len(glyph) < 4 {
		t.Fatalf("no glyph at %v..%v: %d pixels", start, end, len(glyph))
	}
	visible := func() bool {
		n := 0
		for _, pt := range glyph {
			if dark(pt) {
				n++
			}
		}
		return n*10 >= len(glyph)*9
	}
	var offset atomic.Int64
	var fileDone <-chan error
	phases := []string{"idle", "file"}
	if diagnose {
		phases = []string{"file"}
	}
	for _, phase := range phases {
		if phase == "file" {
			fileDone = echoFile(t, ctx, p, nets, viewer, desktop, &offset)
			for offset.Load() == 0 {
				select {
				case e := <-fileDone:
					t.Fatalf("file ended before measurement: %v", e)
				default:
				}
				paint()
				time.Sleep(100 * time.Millisecond)
			}
		}
		first := offset.Load()
		started := time.Now()
		var ms []int64
		rounds := 12
		if compare && !splitAB {
			rounds = 24
		}
		for round := 0; round < rounds; round++ {
			priority := compare && (round%4 == 1 || round%4 == 2)
			split := splitAB && priority
			type result struct {
				sentEpoch int
				r         assistance.Reply
				err       error
			}
			var flight chan result
			focus()
			reset("")
			paint()
			if visible() {
				t.Fatal("previous glyph still present")
			}
			// Local keydown/up pairs arrive at fixed times even while serial frame/input
			// operations are outstanding, like the preview's pending input queue.
			origin := time.Now()
			lastKey := origin.Add(3 * 90 * time.Millisecond)
			nextFrame := origin.Add(160 * time.Millisecond)
			lastPreview := origin
			var maxGap time.Duration
			events := 0
			reportedSlow := false
			var firstPaint time.Time
			var finalKeyStart, finalKeyAck time.Time
			var queuedFrame, queuedInput time.Duration
			// Only charge the overlap after the final key became ready.
			overlap := func(start, end time.Time) time.Duration {
				if start.Before(lastKey) {
					start = lastKey
				}
				return max(0, end.Sub(start))
			}
			for firstPaint.IsZero() || events < 8 {
				if !reportedSlow && time.Since(lastKey) > 12*time.Second {
					t.Logf("slow phase=%s burst=%d events_done=%d final_ack=%v glyph_seen=%v prior_frame=%v prior_input=%v text=%q", phase, round+1, events, !finalKeyAck.IsZero(), !firstPaint.IsZero(), queuedFrame, queuedInput, note.text())
					reportedSlow = true
				}
				if time.Since(lastKey) > 30*time.Second {
					t.Fatalf("burst timeout phase=%s burst=%d events_done=%d text=%q", phase, round+1, events, note.text())
				}
				now := time.Now()
				ready := events < 8 && !now.Before(origin.Add(time.Duration(events/2)*90*time.Millisecond))
				if split {
					if flight != nil {
						select {
						case completed := <-flight:
							flight = nil
							if completed.err != nil {
								t.Fatal(completed.err)
							}
							if !acceptFrame(completed.sentEpoch, completed.r) {
								t.Fatal("control changed during frame")
							}
							stamp := time.Now()
							maxGap = max(maxGap, stamp.Sub(lastPreview))
							lastPreview = stamp
							nextFrame = stamp.Add(160 * time.Millisecond)
							if firstPaint.IsZero() && events >= 7 && visible() {
								firstPaint = stamp
							}
							continue
						default:
						}
					} else if !now.Before(nextFrame) && firstPaint.IsZero() {
						flight = make(chan result, 1)
						cmd := assistance.Command{Op: "frame_delta", ID: id, Epoch: epoch, Baseline: revision}
						finish := ctrl.TrackFrame(id, epoch)
						go func(done chan result) {
							r, e := assistance.Exchange(ctx, client, dest, port, cmd)
							finish(r, e)
							done <- result{cmd.Epoch, r, e}
						}(flight)
					}
				}
				if !split && !now.Before(nextFrame) && (!priority || !ready || now.Sub(lastPreview) >= 320*time.Millisecond) {
					start := time.Now()
					paint()
					stamp := time.Now()
					maxGap = max(maxGap, stamp.Sub(lastPreview))
					lastPreview = stamp
					if events <= 6 {
						queuedFrame += overlap(start, time.Now())
					}
					if firstPaint.IsZero() && events >= 7 && visible() {
						firstPaint = time.Now()
					}
					nextFrame = time.Now().Add(160 * time.Millisecond)
					continue
				}
				if events < 8 && !time.Now().Before(origin.Add(time.Duration(events/2)*90*time.Millisecond)) {
					focus()
					start := time.Now()
					if events%2 == 0 {
						input("keydown", 55, 0)
						if events == 6 {
							finalKeyStart = start
							finalKeyAck = time.Now()
						}
					} else {
						input("keyup", 55, 0)
					}
					if events < 6 {
						queuedInput += overlap(start, time.Now())
					}
					events++
					continue
				}
				time.Sleep(3 * time.Millisecond)
			}
			elapsed := firstPaint.Sub(lastKey).Milliseconds()
			if note.text() != "7777" {
				t.Fatal("fixture input mismatch")
			}
			ms = append(ms, elapsed)
			t.Logf("%s burst=%d priority=%t split=%t max_preview_gap_ms=%d queue_ms=%d prior_frame_ms=%d prior_input_ms=%d final_request_ms=%d ack_to_glyph_ms=%d first_glyph_ms=%d", phase, round+1, priority, split, maxGap.Milliseconds(), finalKeyStart.Sub(lastKey).Milliseconds(), queuedFrame.Milliseconds(), queuedInput.Milliseconds(), finalKeyAck.Sub(finalKeyStart).Milliseconds(), firstPaint.Sub(finalKeyAck).Milliseconds(), elapsed)
		}
		// Keep the lease active while dragging; verify the actual OS selection too.
		reset("77777777777777777777")
		input("keydown", 16, 0)
		input("down", x, y)
		moves := 0
		dragStart := time.Now()
		for until := time.Now().Add(4 * time.Second); time.Now().Before(until); {
			focus()
			if loadedLease {
				cmd := assistance.Command{Op: "frame_delta", ID: id, Epoch: epoch, Baseline: revision}
				finish := ctrl.TrackFrame(id, epoch)
				type result struct {
					frame assistance.Reply
					err   error
				}
				done := make(chan result, 1)
				go func() { r, e := assistance.Exchange(ctx, client, dest, port, cmd); finish(r, e); done <- result{r, e} }()
				input("move", x+900+(moves%3)*100, y)
				res := <-done
				if res.err != nil || !acceptFrame(cmd.Epoch, res.frame) {
					t.Fatal("drag frame lost control", res.err, res.frame.State)
				}
			} else {
				input("move", x+900+(moves%3)*100, y)
				paint()
			}
			sel, _, _ := sm.Call(note.edit, 0xb0, 0, 0)
			if !heldAssist(16) || !heldAssist(1) || uint16(sel) == uint16(sel>>16) {
				t.Fatal("drag released or no selection")
			}
			moves++
		}
		input("up", 0, 0)
		input("keyup", 16, 0)
		if loadedLease {
			t.Logf("tracked drag updates=%d duration=%v", moves, time.Since(dragStart))
		}
		sorted := append([]int64(nil), ms...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		delta := offset.Load() - first
		t.Logf("%s samples_ms=%v median_ms=%.1f p95_ms=%d drag_updates=%d file_confirmed=%d elapsed=%v", phase, ms, float64(sorted[(rounds-1)/2]+sorted[rounds/2])/2, sorted[(95*rounds+99)/100-1], moves, delta, time.Since(started))
		if phase == "file" && (delta <= 0 || offset.Load() >= 12<<20) {
			t.Fatal("file did not overlap entire loaded phase")
		}
	}
	if diagnose && !loadedLease {
		call(assistance.Command{Op: "release"})
		t.Log("CONTROLLED: idle control lane while an independent frame is delayed at the viewer for 2s")
		then := time.Now()
		_, err := assistance.Exchange(ctx, client, dest, port, assistance.Command{Op: "frame_delta", ID: id, Epoch: epoch, Baseline: revision})
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Until(then.Add(2 * time.Second)))
		r, err := assistance.Exchange(ctx, client, dest, port, assistance.Command{Op: "release", ID: id, Epoch: epoch})
		t.Logf("controlled observation state=%s err=%v", r.State, err)
	}
	ctrl.Suspend()
	select {
	case e := <-fileDone:
		if e != nil {
			t.Fatal(e)
		}
		t.Log("12 MiB verified completion")
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
