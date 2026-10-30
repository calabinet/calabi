package mesh

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// filteredTUN wraps the real tun device and drops inbound packets the
// coordinator's filter doesn't allow.
//
// The wrap point is deliberate: Write is WireGuard handing a DECRYPTED,
// AUTHENTICATED packet to the OS, which is the last moment we can refuse it and
// the first moment we know what it is. Read (traffic leaving this machine) is
// never blocked — the far side enforces its own inbound rules, and dropping
// locally would only turn a clear "connection refused by policy" into a
// mysterious timeout — but it IS observed, because the reply to a connection
// this machine opened has to be let back in (see flowtrack.go).
//
// A dropped packet is simply not written. WireGuard counts the write as done,
// which is correct: from its point of view the packet was delivered to the
// device, and the device is what discarded it.
type filteredTUN struct {
	tun.Device
	filter *PacketFilter
	flows  *flowTable
	logger *slog.Logger

	// meter is the relay rate limit's brake. Read pays off what the bind
	// charged BEFORE taking the next batch, which is the only point in this
	// data path where not-reading turns into the application's write()
	// blocking. See relayrate.go.
	//
	// It holds up traffic to every peer, not just the relayed ones: there is
	// one goroutine reading this device for the whole machine
	// (wireguard-go device/send.go RoutineReadFromTUN), so a wait here is a
	// wait for the direct paths too. Known and accepted.
	meter *relayMeter
	// ctx bounds the wait so a shutting-down datapath is not stuck paying.
	ctx context.Context

	// dropped counts refusals (see dpstats.go). The Debug log below is fine for
	// watching a filter work, but it cannot answer "how many did we refuse over
	// the last hour" — and a legitimate refusal and a policy bug look identical
	// from a packet capture, which only shows the hole.
	dropped atomic.Uint64
	probes  atomic.Pointer[probeScheduler]
}

func newFilteredTUN(ctx context.Context, inner tun.Device, filter *PacketFilter, meter *relayMeter, logger *slog.Logger) *filteredTUN {
	if ctx == nil {
		ctx = context.Background()
	}
	return &filteredTUN{
		Device: inner, filter: filter, flows: newFlowTable(),
		meter: meter, ctx: ctx, logger: logger,
	}
}

// Read passes outbound packets through untouched and records the flow each one
// belongs to, so the answer can come back. Recording only while the filter is
// enabled would lose the flows that were opened just before a policy landed, so
// it happens unconditionally — the table is small and costs nothing when unused.
func (t *filteredTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	// Pay for the relayed bytes the previous batches produced before taking
	// more work. Before the cap arrives (or with none) this is a nil check.
	t.meter.settle(t.ctx)
	n, err := t.Device.Read(bufs, sizes, offset)
	for i := 0; i < n && i < len(sizes) && i < len(bufs); i++ {
		end := offset + sizes[i]
		if offset > len(bufs[i]) || end > len(bufs[i]) {
			continue
		}
		if tp, ok := parseTuple(bufs[i][offset:end]); ok {
			t.flows.observeOutbound(tp)
			if s := t.probes.Load(); s != nil {
				s.observe(tp.dst)
			}
		}
	}
	return n, err
}

// allowInbound admits a packet that either answers a conversation this machine
// started or that a rule names. The established check comes first and costs one
// map lookup: it is the common case for anything the user actually initiated,
// and without it a node that appears only as a rule's SOURCE would drop every
// reply it ever gets.
func (t *filteredTUN) allowInbound(pkt []byte) bool {
	tp, ok := parseTuple(pkt)
	if !ok {
		return false // unparseable: we don't know its ports, so we don't guess
	}
	if t.flows.isReply(tp) {
		return true
	}
	return t.filter.allow(tp)
}

// Write forwards only the allowed packets. It compacts the batch in place so a
// dropped packet in the middle doesn't cost the ones after it.
func (t *filteredTUN) Write(bufs [][]byte, offset int) (int, error) {
	if !t.filter.Enabled() {
		t.observeInbound(bufs, offset)
		return t.Device.Write(bufs, offset)
	}
	kept := bufs[:0]
	dropped := 0
	for _, b := range bufs {
		if offset <= len(b) && t.allowInbound(b[offset:]) {
			kept = append(kept, b)
			continue
		}
		dropped++
	}
	if dropped > 0 {
		t.dropped.Add(uint64(dropped))
	}
	if dropped > 0 && t.logger != nil {
		// Debug, not warn: a filter doing its job drops packets continuously, and
		// a warn here would be a self-inflicted log flood.
		t.logger.Debug("mesh: inbound packets dropped by access rules", "count", dropped)
	}
	if len(kept) == 0 {
		return len(bufs), nil // everything filtered; report the batch as consumed
	}
	t.observeInbound(kept, offset)
	n, err := t.Device.Write(kept, offset)
	if err != nil {
		return n, err
	}
	return n + dropped, nil
}

func (t *filteredTUN) observeInbound(bufs [][]byte, offset int) {
	s := t.probes.Load()
	if s == nil {
		return
	}
	for _, b := range bufs {
		if offset >= 0 && offset <= len(b) {
			if tp, ok := parseTuple(b[offset:]); ok {
				s.observe(tp.src)
			}
		}
	}
}

// stats fills in the filter's half of DatapathStats.
func (t *filteredTUN) stats(st *DatapathStats) {
	if s := t.probes.Load(); s != nil {
		st.ProbeSent = s.sent.Load()
		st.ProbeSchedulerRuns = s.runs.Load()
		st.ProbeFailed = s.failed.Load()
		st.ProbeLimited = s.limited.Load()
		st.ProbeHighSent = s.highSent.Load()
		st.ProbeLowSent = s.lowSent.Load()
		st.ProbeRetries = s.retries.Load()
		st.ProbeTimeouts = s.timeouts.Load()
		st.ProbeConfirmed = s.confirmed.Load()
		st.ProbeMaxWaitMicros = s.maxWaitNs.Load() / 1000
		st.ProbePingsReceived = s.replyStats.received.Load()
		st.ProbePongsSent = s.replyStats.sent.Load()
		st.ProbeReplyLimited = s.replyStats.limited.Load()
		st.ProbeReplyDropped = s.replyStats.dropped.Load()
		st.ProbeReplyCoalesced = s.replyStats.coalesced.Load()
		st.ProbeReplyMaxWaitMicros = s.replyStats.maxWaitNs.Load() / 1000
		s.mu.Lock()
		st.ProbeReplyPending = s.replyPending
		s.p.mu.Lock()
		st.ProbePending = len(s.p.pending)
		for _, m := range s.p.learned {
			st.ProbeLearned += len(m)
		}
		for _, sp := range s.peers {
			st.ProbeCandidates += len(sp.candidates)
			if stamp := sp.active.Load(); (stamp != 0 && time.Since(time.Unix(0, stamp)) <= probeIdle) || time.Now().Before(sp.remoteUntil) {
				st.ProbeActive++
				if p, ok := s.p.paths[sp.key]; ok && time.Since(p.confirmed) <= pathTTL {
					st.ProbeDirect++
				} else {
					st.ProbeRelayed++
				}
			} else {
				st.ProbeIdle++
			}
		}
		s.p.mu.Unlock()
		s.mu.Unlock()
	}
	st.FilterDropped = t.dropped.Load()
	st.Flows = t.flows.len()
}
