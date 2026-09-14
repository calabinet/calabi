// reporter.go — flushes the Recorder onto the event bus.
//
// Shape deliberately mirrors platform/usage.Reporter (same cadence, same
// bus, same edge identity fields) so an operator reading either one already
// knows how the other behaves. The difference is that usage reads CUMULATIVE
// byte counters and has to diff them, while this drains a delta that was
// accumulated as events happened — no snapshot state, nothing to get wrong
// across a restart.
package access

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	eventbus "github.com/calabi/calabi/apps/calabi-edge/internal/bus"
)

// SubjectReport is where edges publish access-record batches.
const SubjectReport = "calabi.access.report"

// DefaultReportInterval matches the usage reporter's cadence. A crash loses
// at most this much of the trail, which is why the log line on flush failure
// says how many rows went with it.
const DefaultReportInterval = 60 * time.Second

// maxRowsPerMessage caps one published batch. A busy edge can hold tens of
// thousands of rows at flush time (MaxRows), and one NATS message carrying all
// of them would be megabytes; splitting keeps every message small enough that a
// single oversized publish cannot take the whole flush down with it.
const maxRowsPerMessage = 500

// Report is the JSON wire shape published to SubjectReport.
type Report struct {
	// EdgeNodeID is the reporting edge's numeric control-plane id, and
	// NodeLabel its human name — the same pair, with the same meanings, as
	// usage.Report carries. Through bff-edge both are re-derived from the
	// authenticated certificate rather than trusted from the body.
	EdgeNodeID int64  `json:"edge_node_id"`
	NodeLabel  string `json:"node_label"`
	Rows       []Row  `json:"rows"`
}

// Reporter periodically drains a Recorder onto the bus.
type Reporter struct {
	logger     *slog.Logger
	bus        eventbus.Bus
	rec        *Recorder
	edgeNodeID int64
	nodeLabel  string
	interval   time.Duration
}

// NewReporter builds an unstarted reporter. interval=0 uses the default.
func NewReporter(logger *slog.Logger, bus eventbus.Bus, rec *Recorder, edgeNodeID int64, nodeLabel string, interval time.Duration) *Reporter {
	if interval == 0 {
		interval = DefaultReportInterval
	}
	return &Reporter{
		logger:     logger.With("component", "access.reporter"),
		bus:        bus,
		rec:        rec,
		edgeNodeID: edgeNodeID,
		nodeLabel:  nodeLabel,
		interval:   interval,
	}
}

// Run blocks until ctx is cancelled, flushing on each tick.
//
// The final flush on shutdown is deliberate: a graceful restart is the most
// common way an edge stops, and dropping the last minute of the trail every
// time would put a regular, predictable hole in it.
func (r *Reporter) Run(ctx context.Context) error {
	if r.bus == nil || r.rec == nil {
		r.logger.Info("access reporter: nothing to publish to; idling")
		<-ctx.Done()
		return nil
	}
	tick := time.NewTicker(r.interval)
	defer tick.Stop()
	r.logger.Info("access reporter running", "interval", r.interval)
	for {
		select {
		case <-ctx.Done():
			r.flush()
			return nil
		case <-tick.C:
			r.flush()
		}
	}
}

func (r *Reporter) flush() {
	rows, overflowed := r.rec.Drain()
	if len(rows) == 0 {
		return
	}
	if overflowed > 0 {
		// Worth a line: it means some tunnel saw more than
		// MaxVisitorsPerTunnelHour distinct addresses in an hour, so its log
		// for that hour names some visitors and counts the rest. An operator
		// reading the console needs to know that is expected, not a bug.
		r.logger.Info("access reporter: visitor cap reached; extra connections counted without an address",
			"connections", overflowed, "cap", MaxVisitorsPerTunnelHour)
	}
	sent := 0
	for start := 0; start < len(rows); start += maxRowsPerMessage {
		end := start + maxRowsPerMessage
		if end > len(rows) {
			end = len(rows)
		}
		body, err := json.Marshal(Report{
			EdgeNodeID: r.edgeNodeID,
			NodeLabel:  r.nodeLabel,
			Rows:       rows[start:end],
		})
		if err != nil {
			r.logger.Warn("access reporter: marshal", "err", err, "rows", end-start)
			continue
		}
		if err := r.bus.Publish(SubjectReport, body); err != nil {
			// Say how much of the trail this lost. "publish failed" alone
			// leaves an operator unable to tell a blip from a hole.
			r.logger.Warn("access reporter: publish failed; these access records are lost",
				"err", err, "rows", end-start)
			continue
		}
		sent += end - start
	}
	r.logger.Debug("access reporter: flushed", "rows", sent)
}
