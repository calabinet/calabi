package localweb

// MeshRelayProbe is one leg of the relay path, driven and measured.
//
// WHY: every other number this daemon reports about the relay is end to end —
// a transfer between two nodes, which crosses sender->relay, the relay's
// forwarding, and relay->receiver at once. A bad number there does not say
// which of the three is bad, and the only way round it was to change something,
// redeploy both ends and measure the whole path again.
//
// This drives ONE segment: this node to a relay and back, over the link the
// daemon already holds, using the Ping/Pong echo the relay answers verbatim. No
// second node, no WireGuard, no tun, and not through the send queue — so what
// it reports is the link and the relay's own loops, and the queue's cost can be
// told apart from the path's instead of being mixed into a single figure.
//
// RTTs are MICROSECONDS: a good relay leg is a low double-digit number of
// milliseconds, and rounding that to whole milliseconds throws away most of what
// distinguishes a healthy leg from a degrading one.
//
// ⚠ This struct is duplicated in localweb and statusapi and must stay
// field-identical — see TestMeshRelayProbeShapesAgreeAcrossDaemonKinds.
type MeshRelayProbe struct {
	Relay  string `json:"relay"`
	Sent   uint64 `json:"sent"`
	Echoed uint64 `json:"echoed"`
	// OneWay says there was no return path BY DESIGN. Without it a reader sees
	// echoed=0 and reads 100% loss, which would be a spectacular and entirely
	// fictional network fault.
	OneWay    bool   `json:"one_way"`
	Bytes     uint64 `json:"bytes"`
	ElapsedMs uint64 `json:"elapsed_ms"`
	// BlockedMs is time spent inside the send call. Large during a bulk transfer
	// is expected — the probe waits on the same write mutex — and is itself worth
	// reading, because it separates "the link will not take more" from "nothing
	// was offered".
	BlockedMs uint64 `json:"blocked_ms"`
	RTTMinUs  uint64 `json:"rtt_min_us"`
	RTTP50Us  uint64 `json:"rtt_p50_us"`
	RTTP90Us  uint64 `json:"rtt_p90_us"`
	RTTMaxUs  uint64 `json:"rtt_max_us"`
}
