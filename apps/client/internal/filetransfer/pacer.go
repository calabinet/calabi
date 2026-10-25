package filetransfer

import (
	"context"
	"errors"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	DefaultKbps = 512
	// Production transfers have a separate direct ceiling and conservative start.
	DefaultDeviceKbps         = 256 * 1024
	InitialKbps               = 8 * 1024
	MaxKbps                   = 1024 * 1024
	paceChunk                 = 4096
	BlockSize                 = 256 * 1024
	badSamplesBeforeReduction = 3
	badSamplesBeforePause     = 6
)

// Pacer is shared by ALL file tasks in one direction on a device. A small burst
// prevents a newly started task from dumping a full block into the mesh queue.
// Kbps follows the existing mesh quota convention: 1024 bits, not 1000.
type Pacer struct {
	mu          sync.Mutex
	lim         *rate.Limiter
	ceiling     int
	configured  int
	current     int
	baseline    time.Duration
	badSamples  int
	pausedUntil time.Time
}

func NewPacer(kbps int) (*Pacer, error) {
	if kbps < 1 || kbps > MaxKbps {
		return nil, errors.New("file rate is outside 1..1048576 kbps")
	}
	return &Pacer{lim: rate.NewLimiter(rate.Limit(kbps)*128, paceChunk), configured: kbps, ceiling: kbps, current: kbps}, nil
}

func (p *Pacer) Wait(ctx context.Context, n int) error {
	// Serialize reservations so concurrent tasks cannot build an unbounded queue
	// of future tokens or stack independent allowances.
	for n > 0 {
		p.mu.Lock()
		pause := time.Until(p.pausedUntil)
		if pause > 0 {
			p.mu.Unlock()
			if err := wait(ctx, min(pause, 100*time.Millisecond)); err != nil {
				return err
			}
			continue
		}
		// At low rates a full 4 KiB wait could hide feedback for 32 seconds.
		// Reserve at most about 100 ms while serializing the shared limiter.
		part := min(n, paceChunk, max(1, p.current*128/10))
		err := p.lim.WaitN(ctx, part)
		p.mu.Unlock()
		if err != nil {
			return err
		}
		n -= part
	}
	return nil
}

func (p *Pacer) Kbps() int    { p.mu.Lock(); defer p.mu.Unlock(); return p.current }
func (p *Pacer) Ceiling() int { p.mu.Lock(); defer p.mu.Unlock(); return p.ceiling }

func (p *Pacer) startAt(kbps int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.current = max(1, min(p.ceiling, kbps))
	p.lim.SetLimit(rate.Limit(p.current) * 128)
}
func (p *Pacer) SetDeviceLimit(kbps int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ceiling = max(1, min(p.configured, kbps))
	p.current = min(p.current, p.ceiling)
	p.lim.SetLimit(rate.Limit(p.current) * 128)
}

// Fixed budgets do not run congestion probes; lifting their ceiling must also
// lift the effective rate. Adaptive flow budgets use SetDeviceLimit instead.
func (p *Pacer) fixedLimit(kbps int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ceiling = max(1, min(p.configured, kbps))
	p.current = p.ceiling
	p.lim.SetLimit(rate.Limit(p.current) * 128)
}

// A different destination/path needs its own latency baseline. Keep the shared
// rate/burst budget intact; do not compare a WAN peer to an earlier LAN RTT.
func (p *Pacer) ResetProbe() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.baseline = 0
	p.badSamples = 0
	p.pausedUntil = time.Time{}
}

// A human pause is not path congestion. Resume conservatively within the
// current policy ceiling instead of inheriting accumulated pause backoff.
func (p *Pacer) resumeProbe() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.baseline, p.badSamples, p.pausedUntil = 0, 0, time.Time{}
	p.current = min(p.ceiling, InitialKbps)
	p.lim.SetLimit(rate.Limit(p.current) * 128)
}

func (p *Pacer) cap(kbps int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ceiling = min(p.ceiling, kbps)
	p.current = min(p.current, p.ceiling)
	p.lim.SetLimit(rate.Limit(p.current) * 128)
}

// Observe reacts to a separate small authenticated request, not to the transfer
// block's own deliberately paced duration. This is a conservative heuristic,
// not an estimate of the organization's unused bandwidth or a QoS guarantee.
func (p *Pacer) Observe(rtt time.Duration, failed bool) {
	p.observeAt(rtt, failed, time.Now())
}

func (p *Pacer) observeAt(rtt time.Duration, failed bool, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.pausedUntil.IsZero() {
		if now.Before(p.pausedUntil) {
			// A probe must not continually move the quiet period into the future.
			// Wait has stopped this flow; repeating the same latency observation
			// is not evidence for another multiplicative reduction.
			return
		}
		if failed {
			// Keep a finite retry interval while the control path is unavailable.
			p.pausedUntil = now.Add(5 * time.Second)
			return
		}
		// This successful sample follows a quiet flow. Relearn its unloaded
		// latency: a historical minimum must not permanently freeze a path
		// whose underlying RTT changed. Retain the reduced rate for recovery.
		p.baseline, p.badSamples, p.pausedUntil = rtt, 0, time.Time{}
		return
	}
	if rtt > 0 && (p.baseline == 0 || rtt < p.baseline) {
		p.baseline = rtt
	}
	if failed || (p.baseline > 0 && rtt > p.baseline+max(50*time.Millisecond, p.baseline)) {
		p.badSamples++
		// Confirm a consecutive window before each reduction. A healthy sample
		// clears the window, so isolated latency spikes cannot ratchet speed down.
		if p.badSamples%badSamplesBeforeReduction != 0 {
			return
		}
		if p.badSamples >= badSamplesBeforePause {
			p.pausedUntil = now.Add(5 * time.Second)
		}
		p.current = max(1, p.current/2)
	} else {
		p.badSamples = 0
		p.pausedUntil = time.Time{}
		p.current = min(p.ceiling, p.current+max(1, p.current/4))
	}
	p.lim.SetLimit(rate.Limit(p.current) * 128)
}
