package filetransfer

import (
	"testing"
	"time"
)

func TestIsolatedBadSamplesCannotRatchetRateDown(t *testing.T) {
	for _, failed := range []bool{false, true} {
		p, _ := NewPacer(32768)
		p.startAt(InitialKbps)
		now := time.Now()
		p.observeAt(10*time.Millisecond, false, now)
		for cycle := 0; cycle < 8; cycle++ {
			before := p.Kbps()
			for n := 1; n <= 2; n++ {
				p.observeAt(120*time.Millisecond, failed, now.Add(time.Duration(cycle*3+n)*time.Second))
				if p.Kbps() != before || !p.pausedUntil.IsZero() {
					t.Fatal("one or two bad samples throttled the flow", failed, cycle, n, p.Kbps())
				}
			}
			p.observeAt(10*time.Millisecond, false, now.Add(time.Duration(cycle*3+3)*time.Second))
			if p.badSamples != 0 || p.Kbps() < before || p.Kbps() > p.Ceiling() {
				t.Fatal("healthy probe did not reset the consecutive window")
			}
		}
	}
}

func TestSustainedBadSamplesReduceOncePerConfirmedWindow(t *testing.T) {
	p, _ := NewPacer(32768)
	p.startAt(InitialKbps)
	now := time.Now()
	p.observeAt(10*time.Millisecond, false, now)
	initial := p.Kbps()
	for n := 1; n <= 6; n++ {
		p.observeAt(120*time.Millisecond, false, now.Add(time.Duration(n)*2*time.Second))
		want := initial
		if n >= 3 {
			want /= 2
		}
		if n >= 6 {
			want /= 2
		}
		if p.Kbps() != want {
			t.Fatal("wrong confirmed-window reduction", n, p.Kbps(), want)
		}
		if (n == 6) != !p.pausedUntil.IsZero() {
			t.Fatal("quiet period triggered at wrong anomaly count", n)
		}
	}
}

func TestLatencyBackoffCannotExtendItselfForever(t *testing.T) {
	p, _ := NewPacer(32768)
	p.startAt(InitialKbps)
	now := time.Now()
	p.observeAt(10*time.Millisecond, false, now)
	for i := 1; i <= badSamplesBeforePause; i++ {
		p.observeAt(120*time.Millisecond, false, now.Add(time.Duration(i)*2*time.Second))
	}
	deadline, reduced := p.pausedUntil, p.Kbps()
	if deadline.IsZero() || reduced >= InitialKbps {
		t.Fatal("congestion did not yield")
	}
	for _, delta := range []time.Duration{-4 * time.Second, -3 * time.Second, -time.Second} {
		p.observeAt(120*time.Millisecond, false, deadline.Add(delta))
		if p.pausedUntil != deadline || p.Kbps() != reduced {
			t.Fatal("quiet probes extended the pause or compounded throttling")
		}
	}
	p.observeAt(120*time.Millisecond, false, deadline.Add(time.Millisecond))
	if !p.pausedUntil.IsZero() || p.Kbps() != reduced || p.baseline != 120*time.Millisecond {
		t.Fatal("quiet-path sample did not recover the controller")
	}
	for i := 1; i <= 8; i++ {
		p.observeAt(120*time.Millisecond, false, deadline.Add(time.Duration(i)*2*time.Second))
	}
	if p.Kbps() <= reduced || !p.pausedUntil.IsZero() || p.Kbps() > p.Ceiling() {
		t.Fatal("stable changed RTT stayed frozen or exceeded policy", p.Kbps())
	}
}

func TestUnavailableProbeDoesNotResumeAndRecoveryRetainsPolicy(t *testing.T) {
	p, _ := NewPacer(128)
	now := time.Now()
	for i := 0; i < badSamplesBeforePause; i++ {
		p.observeAt(0, true, now.Add(time.Duration(i)*time.Second))
	}
	deadline, reduced := p.pausedUntil, p.Kbps()
	p.observeAt(0, true, deadline.Add(time.Second))
	if !p.pausedUntil.After(deadline) || p.Kbps() != reduced {
		t.Fatal("unavailable peer resumed or compounded throttling")
	}
	p.observeAt(100*time.Millisecond, false, p.pausedUntil.Add(time.Millisecond))
	if !p.pausedUntil.IsZero() || p.Kbps() != reduced {
		t.Fatal("recovery skipped conservative rate")
	}
	for i := 0; i < 30; i++ {
		p.Observe(100*time.Millisecond, false)
	}
	if p.Kbps() != 128 {
		t.Fatal("recovery bypassed or failed to recover the low policy ceiling", p.Kbps())
	}
}
