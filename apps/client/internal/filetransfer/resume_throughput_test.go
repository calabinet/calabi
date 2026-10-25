package filetransfer

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestThroughputResetExcludesHumanPause(t *testing.T) {
	var meter throughput
	now := time.Unix(100, 0)
	meter.add(now, 4096)
	rate, ok := meter.add(now.Add(time.Second), 65536)
	if !ok || rate != 65536 {
		t.Fatal(rate, ok)
	}
	meter.reset()
	if rate, ok = meter.add(now.Add(time.Hour), 4096); ok || rate != 0 {
		t.Fatal("pause retained old rate")
	}
	rate, ok = meter.add(now.Add(time.Hour+time.Second), 65536)
	if !ok || rate != 65536 {
		t.Fatal("human pause diluted resumed rate", rate, ok)
	}
}

func TestLateUploadActivityCannotRestorePausedRate(t *testing.T) {
	j := outgoingJob{record: outgoingRecord{Job: Job{State: "sending", Progress: BatchProgress{Transfer: Transfer{ID: "file", State: "paused", Offset: 100}}}}}
	j.report(BatchProgress{activity: &transferActivity{id: "file", rate: 65536, remaining: 1, at: time.Now()}})
	if j.record.Job.RateBps != 0 || j.record.Job.Progress.Transfer.Offset != 100 || j.record.Job.Progress.Transfer.State != "paused" {
		t.Fatal("late body writer changed paused presentation")
	}
}

func TestResumeProbeClearsBackoffWithinPolicy(t *testing.T) {
	for _, ceiling := range []int{128, 32768} {
		p, _ := NewPacer(ceiling)
		for i := 0; i < 12; i++ {
			p.Observe(time.Second, true)
		}
		p.resumeProbe()
		if p.Kbps() != min(ceiling, InitialKbps) || p.Ceiling() != ceiling || !p.pausedUntil.IsZero() || p.badSamples != 0 || p.baseline != 0 {
			t.Fatal("resume kept backoff or bypassed policy", p.Kbps(), p.Ceiling())
		}
	}
}

func TestSlowBlockReportsActivityBeforeDurableAcknowledgement(t *testing.T) {
	w, r, _ := stateSyncPair(t)
	w.Agent.budget.fixedLimit(512) // 64 KiB/s: a full block exceeds the old 3s expiry.
	data := bytes.Repeat([]byte("s"), 512<<10)
	source, err := w.Stage(context.Background(), bytes.NewReader(data), "slow.bin", int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Send(netip.MustParseAddr("127.0.0.1"), []string{source.ID}, ""); err != nil {
		t.Fatal(err)
	}
	syncUntil(t, func() bool { return len(r.List()) == 1 })
	if err = r.Decide(r.List()[0].ID, true); err != nil {
		t.Fatal(err)
	}
	syncUntil(t, func() bool { return w.Jobs()[0].RateBps > 0 && r.List()[0].RateBps > 0 })
	if w.Jobs()[0].Progress.Transfer.Offset != 0 || r.List()[0].Offset != 0 {
		t.Fatal("slow-block metrics arrived only after durable acknowledgement")
	}
	deadline := time.Now().Add(3300 * time.Millisecond)
	for time.Now().Before(deadline) {
		j := w.Jobs()[0]
		if j.RateBps <= 0 || j.RemainingSeconds <= 0 {
			t.Fatal("active slow upload lost rate/ETA", j.RateBps, j.RemainingSeconds)
		}
		if j.RateBps > 128<<10 {
			t.Fatal("acknowledged offset was counted as instantaneous speed", j.RateBps)
		}
		time.Sleep(100 * time.Millisecond)
	}
	syncUntil(t, func() bool { return w.Jobs()[0].State == "completed" })
	var saved bytes.Buffer
	if err = r.CopyCompleted(context.Background(), r.List()[0].ID, &saved); err != nil || !bytes.Equal(saved.Bytes(), data) {
		t.Fatal("slow transfer body changed", err)
	}
}

type interruptedPauseTransport struct {
	base        http.RoundTripper
	pause       func() error
	interrupted atomic.Bool
}

func (p *interruptedPauseTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodPut && p.interrupted.CompareAndSwap(false, true) {
		if err := p.pause(); err != nil {
			return nil, err
		}
		return nil, errors.New("recipient paused in-flight upload")
	}
	return p.base.RoundTrip(r)
}

func TestRecipientPauseIsNotCongestionFeedback(t *testing.T) {
	testRecipientPauseFeedback(t, false)
}

func TestQuickRecipientPauseResumeIsNotCongestionFeedback(t *testing.T) {
	testRecipientPauseFeedback(t, true)
}

func testRecipientPauseFeedback(t *testing.T, quick bool) {
	t.Helper()
	w, r, _ := stateSyncPair(t)
	s, err := w.Agent.Sender(netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	transport := &interruptedPauseTransport{base: s.client.Transport, pause: func() error {
		id := r.List()[0].ID
		if err := r.SetPaused(id, true); err != nil {
			return err
		}
		if quick {
			return r.SetPaused(id, false)
		}
		return nil
	}}
	s.client.Transport = transport
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	paused := make(chan struct{}, 1)
	done := make(chan error, 1)
	var ticket BatchTicket
	go func() {
		done <- s.SendBatch(ctx, []Source{{Reader: bytes.NewReader(make([]byte, 512<<10)), Name: "pause.bin", Size: 512 << 10}}, &ticket, func(BatchTicket) error { return nil }, func(p BatchProgress) {
			if p.Transfer.State == "paused" || quick && transport.interrupted.Load() && p.Transfer.State == "accepted" {
				select {
				case paused <- struct{}{}:
				default:
				}
			}
		})
	}()
	syncUntil(t, func() bool { return len(r.List()) == 1 })
	if err = r.Decide(r.List()[0].ID, true); err != nil {
		t.Fatal(err)
	}
	select {
	case <-paused:
	case err := <-done:
		t.Fatal("did not wait for recipient pause", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if got := s.flow.Kbps(); got != InitialKbps {
		t.Fatal("human pause reduced adaptive rate as if congested", got)
	}
	if err = r.SetPaused(r.List()[0].ID, false); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}
