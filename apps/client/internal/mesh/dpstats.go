package mesh

// Datapath accounting.
//
// The mesh datapath had no counters at all. That is a problem the first time
// anyone asks the only question that matters when a transfer is slow — "are we
// dropping these, or is the network?" — because the honest answer was "there is
// no way to tell", and the two have opposite fixes.
//
// The counters below are chosen to form a CHAIN, not a pile. Read end to end,
// across both nodes, they localise a loss to exactly one hop:
//
//	sender.TxDirect            packets we put on the wire
//	  ↓ (difference = the WAN, or the receiver's kernel socket buffer)
//	receiver.SockRxPackets     packets the receiving host actually read
//	  ↓ (difference = QueueDropped: our own bounded queue overflowed)
//	receiver.RxDirect          packets handed to WireGuard
//	  ↓ (difference = FilterDropped: the access-rule filter refused them)
//	                           packets written to the tun
//
// Any single counter in isolation says very little; the differences are the
// whole point.
//
// It is also why SockRxPackets counts EVERY datagram read off the socket, DISCO
// and STUN included, rather than only WireGuard ones: it has to be comparable
// with what the far side says it sent, and the far side's probes are part of
// that.
//
// JSON names also serve the mobile API. The desktop wire shape is
// localweb.MeshDatapath / statusapi.MeshDatapath, converted from this one
// directly — so a field added here and not there stops COMPILING, which is a
// better guard than a third set of tags nobody checks.
type DatapathStats struct {
	ProbeSent               uint64 `json:"probe_sent"`
	ProbeFailed             uint64 `json:"probe_failed"`
	ProbeLimited            uint64 `json:"probe_limited"`
	ProbeActive             int    `json:"probe_active"`
	ProbeCandidates         int    `json:"probe_candidates"`
	ProbeSchedulerRuns      uint64 `json:"probe_scheduler_runs"`
	ProbeHighSent           uint64 `json:"probe_high_sent"`
	ProbeLowSent            uint64 `json:"probe_low_sent"`
	ProbeRetries            uint64 `json:"probe_retries"`
	ProbeTimeouts           uint64 `json:"probe_timeouts"`
	ProbeConfirmed          uint64 `json:"probe_confirmed"`
	ProbeMaxWaitMicros      uint64 `json:"probe_max_wait_micros"`
	ProbePingsReceived      uint64 `json:"probe_pings_received"`
	ProbePongsSent          uint64 `json:"probe_pongs_sent"`
	ProbeReplyLimited       uint64 `json:"probe_reply_limited"`
	ProbeReplyDropped       uint64 `json:"probe_reply_dropped"`
	ProbeReplyCoalesced     uint64 `json:"probe_reply_coalesced"`
	ProbeReplyPending       int    `json:"probe_reply_pending"`
	ProbeReplyMaxWaitMicros uint64 `json:"probe_reply_max_wait_micros"`
	ProbePending            int    `json:"probe_pending"`
	ProbeLearned            int    `json:"probe_learned"`
	ProbeIdle               int    `json:"probe_idle"`
	ProbeDirect             int    `json:"probe_direct"`
	ProbeRelayed            int    `json:"probe_relayed"`
	// --- the direct-path UDP socket -----------------------------------------
	// Everything read off / written to the hole-punched socket, all kinds
	// (WireGuard, DISCO, STUN). Zero on a node that has never punched a path.
	SockRxPackets uint64 `json:"sock_rx_packets"`
	SockRxBytes   uint64 `json:"sock_rx_bytes"`
	SockTxPackets uint64 `json:"sock_tx_packets"`
	SockTxBytes   uint64 `json:"sock_tx_bytes"`
	SockTxErrors  uint64 `json:"sock_tx_errors"`
	// The buffer sizes the kernel actually settled on (see sockbuf.go). A small
	// SockRxBufBytes on a fast path is a loss source that no counter here can
	// see, because those packets are discarded before we ever read them.
	SockRxBufBytes int `json:"sock_rx_buf_bytes"`
	SockTxBufBytes int `json:"sock_tx_buf_bytes"`

	// --- the bind's inbound queue -------------------------------------------
	// QueueDropped is the drop that used to be a bare `default:` with a comment
	// claiming WireGuard would retransmit. It does not: WireGuard retransmits
	// handshakes, never transport data. Every packet counted here is a hole the
	// inner TCP has to discover by timeout.
	QueueDepth   int    `json:"queue_depth"`
	QueueCap     int    `json:"queue_cap"`
	QueueDropped uint64 `json:"queue_dropped"`

	// --- transport split ----------------------------------------------------
	// Send picks direct-or-relay per packet, so a path that flickers splits one
	// TCP stream across two transports with very different latencies. That is
	// invisible as a rate, but shows up here as both counters climbing at once —
	// and as reordering in a capture.
	RxDirect       uint64 `json:"rx_direct"`
	RxRelay        uint64 `json:"rx_relay"`
	TxDirect       uint64 `json:"tx_direct"`
	TxRelay        uint64 `json:"tx_relay"`
	TxDirectErrors uint64 `json:"tx_direct_errors"`
	TxRelayErrors  uint64 `json:"tx_relay_errors"`
	// TxRelayDropped is traffic THIS node refused to send late over a relay
	// (derp/sendq.go). Not a failure: a relay that never drops turns the tunnel
	// into a reliable link, and the TCP inside it — which reacts to loss, never
	// to delay — answers by filling seconds of queue. This is the congestion
	// signal being delivered on purpose, and it is counted for exactly that
	// reason: a deliberate drop is the last thing that should be invisible.
	TxRelayDropped uint64 `json:"tx_relay_dropped"`
	// TxRelayBlockedMs is how long the relay writers sat inside conn.Write. Against
	// the wall clock of a transfer it answers "blocked or starved?" — the question
	// TxRelayDropped on its own cannot, because a shed frame looks the same either
	// way and the two have nothing in common but the symptom.
	TxRelayBlockedMs uint64 `json:"tx_relay_blocked_ms"`
	// TxRelaySockBuf is the kernel send buffer this node is currently asking for
	// behind the relay socket, in bytes; 0 means the socket is left to the
	// kernel's own auto-tuning. TxRelayRateBps is the windowed-maximum send rate
	// that size was derived from. Both come from derp/sndbuf.go, and both are
	// reported for the same reason the drop count is: a datapath that resizes its
	// own buffers from its own measurements is exactly the thing that must not be
	// doing it invisibly when the answer looks wrong.
	TxRelaySockBuf uint64 `json:"tx_relay_sockbuf"`
	TxRelayRateBps uint64 `json:"tx_relay_rate_bps"`

	// --- the inbound access-rule filter -------------------------------------
	// FilterDropped is decrypted, authenticated traffic refused by the meshnet's
	// rules. Legitimate when the rules say so — and indistinguishable from a bug
	// until someone can see the number.
	FilterDropped uint64 `json:"filter_dropped"`
	Flows         int    `json:"flows"`
}
