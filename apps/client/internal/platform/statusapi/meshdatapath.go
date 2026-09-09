package statusapi

// MeshDatapath is the node's own packet accounting for /v1/mesh.
//
// WHY IT EXISTS: the mesh datapath used to report nothing but WireGuard's own
// per-peer byte counters, which say what got encrypted and decrypted and
// nothing about what went missing on the way. When a transfer is slow, the
// only question worth asking is "are WE dropping these, or is the network?",
// and until these counters existed there was no way to answer it — the two
// have opposite fixes.
//
// Read as DIFFERENCES across the two nodes, they localise a loss to one hop:
// the sender's tx_direct minus the receiver's sock_rx_packets is the WAN (or
// the receiver's kernel socket buffer, which is why sock_rx_buf_bytes sits
// next to it); sock_rx_packets minus rx_direct is queue_dropped, our own
// overflow; and filter_dropped is traffic the access rules refused after
// decryption.
//
// ⚠ This struct is duplicated in localweb and statusapi and must stay
// field-identical — see TestMeshShapesAgreeAcrossDaemonKinds.
type MeshDatapath struct {
	// The hole-punched UDP socket: every datagram, WireGuard and probes alike.
	SockRxPackets uint64 `json:"sock_rx_packets"`
	SockRxBytes   uint64 `json:"sock_rx_bytes"`
	SockTxPackets uint64 `json:"sock_tx_packets"`
	SockTxBytes   uint64 `json:"sock_tx_bytes"`
	SockTxErrors  uint64 `json:"sock_tx_errors"`
	// What the kernel actually granted for buffers. A userspace datapath drops
	// whatever does not fit here while its reader is descheduled, before any
	// counter above can see it.
	SockRxBufBytes int `json:"sock_rx_buf_bytes"`
	SockTxBufBytes int `json:"sock_tx_buf_bytes"`
	// The bind's inbound queue. queue_dropped is the one place this datapath
	// discards traffic of its own accord; WireGuard does NOT retransmit what is
	// lost here (it retransmits handshakes, never transport data), so each one
	// is a hole the inner TCP finds by timeout.
	QueueDepth   int    `json:"queue_depth"`
	QueueCap     int    `json:"queue_cap"`
	QueueDropped uint64 `json:"queue_dropped"`
	// Transport split. Send picks direct-or-relay per packet, so a flickering
	// path splits one stream across two very different latencies — invisible as
	// a rate, obvious here as both counters climbing together.
	RxDirect       uint64 `json:"rx_direct"`
	RxRelay        uint64 `json:"rx_relay"`
	TxDirect       uint64 `json:"tx_direct"`
	TxRelay        uint64 `json:"tx_relay"`
	TxDirectErrors uint64 `json:"tx_direct_errors"`
	TxRelayErrors  uint64 `json:"tx_relay_errors"`
	// Traffic this node refused to send late over a relay — the congestion
	// signal a TCP-based relay otherwise swallows. Deliberate, and counted.
	TxRelayDropped uint64 `json:"tx_relay_dropped"`
	// How long the relay writers spent inside conn.Write: blocked for most of a
	// transfer means the link would not take more, near zero means the writer was
	// idle while frames were shed and the throttle is upstream of the datapath.
	TxRelayBlockedMs uint64 `json:"tx_relay_blocked_ms"`
	TxRelaySockBuf   uint64 `json:"tx_relay_sockbuf"`
	TxRelayRateBps   uint64 `json:"tx_relay_rate_bps"`
	// Decrypted, authenticated traffic the meshnet's access rules refused.
	// Legitimate when the rules say so, and indistinguishable from a policy bug
	// until someone can see the number.
	FilterDropped uint64 `json:"filter_dropped"`
	Flows         int    `json:"flows"`
}
