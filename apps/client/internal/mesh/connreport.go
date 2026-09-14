package mesh

import (
	"context"
	"log/slog"
	"time"
)

// Reporting who this node exchanged traffic with — the node's half of the
// data-plane audit trail (calabi-coord core/connrecord.go).
//
// The node does the arithmetic because it is the only party that can. WireGuard
// keeps CUMULATIVE counters per peer and resets them whenever the peer is
// reconfigured, so a total is meaningless to a reader: it double-counts across a
// restart and goes backwards across a reset. Two readings and the difference
// between them is a number that means something, and only the holder of both
// readings can produce it.
//
// What is deliberately NOT sent: the endpoint, the public IP, the port. Only the
// peer, the window, the byte counts and direct-vs-relay. That line is the whole
// of why this is allowed to exist as history at all — see the note on
// ReportConnections in coord.proto and mesh-console-ux-plan

// connReportInterval is how often a node reports. Short enough that a crash
// costs minutes rather than an hour of trail; the coordinator folds these into
// hourly rows, so reporting more often does not multiply stored rows.
const connReportInterval = 5 * time.Minute

// snapshotter is a datapath that can report its live per-peer counters.
type snapshotter interface{ Snapshot() Status }

// connCounters is one peer's last reading.
type connCounters struct {
	rx, tx int64
}

// connReporter turns successive Snapshots into per-window deltas.
//
// Not safe for concurrent use: it is owned by the single reporting loop.
type connReporter struct {
	last map[string]connCounters
	// since is the start of the window being accumulated. Zero until the first
	// reading, which is a BASELINE and reports nothing — otherwise a node that
	// had been up for a week would attribute the whole week to its first window.
	since time.Time
}

func newConnReporter() *connReporter {
	return &connReporter{last: map[string]connCounters{}}
}

// sample reads the current counters and returns what to report for the window
// that just closed. nil on the first call (baseline) and whenever nothing moved.
func (r *connReporter) sample(peers []PeerStatus, now time.Time) []ConnSample {
	cur := make(map[string]connCounters, len(peers))
	for _, p := range peers {
		cur[p.PublicKey] = connCounters{rx: p.RxBytes, tx: p.TxBytes}
	}
	if r.since.IsZero() {
		r.last, r.since = cur, now
		return nil
	}
	out := make([]ConnSample, 0, len(peers))
	for _, p := range peers {
		c := cur[p.PublicKey]
		prev, seen := r.last[p.PublicKey]
		dRx, dTx := c.rx, c.tx
		if seen {
			dRx, dTx = c.rx-prev.rx, c.tx-prev.tx
			// A counter that went backwards means the peer was reconfigured and
			// WireGuard started it again from zero. The current value IS the
			// delta then; subtracting would give a negative, and clamping to zero
			// would silently drop everything since the reset.
			if dRx < 0 {
				dRx = c.rx
			}
			if dTx < 0 {
				dTx = c.tx
			}
		}
		if dRx == 0 && dTx == 0 {
			// A peer in the netmap that nobody talked to is not a connection, and
			// writing a row for it would bury the real ones.
			continue
		}
		out = append(out, ConnSample{
			PeerNodeKey: p.PublicKey,
			WindowStart: r.since,
			WindowEnd:   now,
			BytesTx:     dTx,
			BytesRx:     dRx,
			Path:        p.Path,
		})
	}
	r.last, r.since = cur, now
	if len(out) == 0 {
		return nil
	}
	return out
}

// ConnSample is one peer over one window, as this node measured it.
type ConnSample struct {
	PeerNodeKey string
	WindowStart time.Time
	WindowEnd   time.Time
	BytesTx     int64
	BytesRx     int64
	Path        string
}

// connReportLoop samples and reports until ctx ends.
//
// A failed report is DROPPED, not retried. The samples are deltas, so a retry
// would double-count everything that did land; and the window it covers is
// already folded into the next one only in the sense that the counters keep
// climbing — the honest outcome of a failed report is a gap, which is what an
// unreachable coordinator actually means. A silent gap is worse than a logged
// one, hence the warning.
func (c *Controller) connReportLoop(ctx context.Context) {
	if c.Coord == nil {
		return
	}
	// Same optional-interface idiom as directTransport / sleepResumer: the
	// Datapath contract is SetConfig + Close, and a dry-run datapath has no
	// counters to read. Nothing to report then, rather than a nil deref.
	dp, ok := c.Datapath.(snapshotter)
	if !ok {
		return
	}
	r := newConnReporter()
	t := time.NewTicker(connReportInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			samples := r.sample(dp.Snapshot().Peers, now)
			if len(samples) == 0 {
				continue
			}
			if err := c.Coord.ReportConnections(ctx, c.registerParams(), samples); err != nil {
				c.logf(slog.LevelDebug, "mesh: connection report failed; this window is a gap in the trail", "peers", len(samples), "err", err)
			}
		}
	}
}

// logf is a nil-safe logger shim: the Controller's Logger is optional in tests.
func (c *Controller) logf(level slog.Level, msg string, args ...any) {
	if c.Logger != nil {
		c.Logger.Log(context.Background(), level, msg, args...)
	}
}
