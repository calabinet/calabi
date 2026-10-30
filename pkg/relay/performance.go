package relay

import (
	"encoding/binary"
	"sync/atomic"
)

type performanceCounters struct {
	handshakes atomic.Uint64
	keepalives atomic.Uint64
	data       atomic.Uint64
	unknown    atomic.Uint64
	linkPings  atomic.Uint64
	queued     atomic.Uint64
	offline    atomic.Uint64
}

// PerformanceSnapshot counts received ciphertext by public WireGuard framing,
// without decrypting or retaining packet bodies. Queue gauges cover live links.
type PerformanceSnapshot struct {
	Clients            int    `json:"clients"`
	HandshakePackets   uint64 `json:"handshake_packets"`
	KeepalivePackets   uint64 `json:"keepalive_packets"`
	DataPackets        uint64 `json:"data_packets"`
	UnknownPackets     uint64 `json:"unknown_packets"`
	LinkPings          uint64 `json:"link_pings"`
	QueuedPackets      uint64 `json:"queued_packets"`
	OfflinePackets     uint64 `json:"offline_packets"`
	QueueDepth         int    `json:"queue_depth"`
	QueueDroppedActive uint64 `json:"queue_dropped_active"`
}

func (h *Hub) countPacket(pkt []byte) {
	if len(pkt) >= 4 {
		switch binary.LittleEndian.Uint32(pkt[:4]) {
		case 1:
			if len(pkt) == 148 {
				h.performance.handshakes.Add(1)
				return
			}
		case 2:
			if len(pkt) == 92 {
				h.performance.handshakes.Add(1)
				return
			}
		case 3:
			if len(pkt) == 64 {
				h.performance.handshakes.Add(1)
				return
			}
		case 4:
			if len(pkt) == 32 {
				h.performance.keepalives.Add(1)
				return
			}
			if len(pkt) > 32 {
				h.performance.data.Add(1)
				return
			}
		}
	}
	h.performance.unknown.Add(1)
}

func (h *Hub) Performance() PerformanceSnapshot {
	p := &h.performance
	out := PerformanceSnapshot{HandshakePackets: p.handshakes.Load(), KeepalivePackets: p.keepalives.Load(), DataPackets: p.data.Load(), UnknownPackets: p.unknown.Load(), LinkPings: p.linkPings.Load(), QueuedPackets: p.queued.Load(), OfflinePackets: p.offline.Load()}
	h.mu.RLock()
	defer h.mu.RUnlock()
	out.Clients = len(h.clients)
	for _, c := range h.clients {
		out.QueueDepth += len(c.sendq.ch)
		out.QueueDroppedActive += c.sendq.Dropped()
	}
	return out
}
