package mesh

import (
	"log/slog"

	"golang.zx2c4.com/wireguard/tun"
)

// filteredTUN wraps the real tun device and drops inbound packets the
// coordinator's filter doesn't allow (MESH.5b).
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
}

func newFilteredTUN(inner tun.Device, filter *PacketFilter, logger *slog.Logger) *filteredTUN {
	return &filteredTUN{Device: inner, filter: filter, flows: newFlowTable(), logger: logger}
}

// Read passes outbound packets through untouched and records the flow each one
// belongs to, so the answer can come back. Recording only while the filter is
// enabled would lose the flows that were opened just before a policy landed, so
// it happens unconditionally — the table is small and costs nothing when unused.
func (t *filteredTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.Device.Read(bufs, sizes, offset)
	for i := 0; i < n && i < len(sizes) && i < len(bufs); i++ {
		end := offset + sizes[i]
		if offset > len(bufs[i]) || end > len(bufs[i]) {
			continue
		}
		if tp, ok := parseTuple(bufs[i][offset:end]); ok {
			t.flows.observeOutbound(tp)
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
	if dropped > 0 && t.logger != nil {
		// Debug, not warn: a filter doing its job drops packets continuously, and
		// a warn here would be a self-inflicted log flood.
		t.logger.Debug("mesh: inbound packets dropped by access rules", "count", dropped)
	}
	if len(kept) == 0 {
		return len(bufs), nil // everything filtered; report the batch as consumed
	}
	n, err := t.Device.Write(kept, offset)
	if err != nil {
		return n, err
	}
	return n + dropped, nil
}
