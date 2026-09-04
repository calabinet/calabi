// Package stunserver is calabi-derp's STUN responder: it tells a mesh node the
// public (reflexive) address a relay sees it at, the primitive a node needs to
// discover its NAT-mapped endpoint for hole punching (MESH.4). It answers only
// binding requests, reports only the observed source address, holds no state, and
// sees no secrets (STUN is plaintext, unrelated to the encrypted relay path).
package stunserver

import (
	"log/slog"
	"net"
	"net/netip"

	"github.com/calabi/calabi/pkg/mesh-proto/stun"
)

// Serve answers STUN binding requests on conn until it is closed (returns on the
// read error a Close produces). Non-STUN / non-request datagrams are ignored.
func Serve(conn *net.UDPConn, logger *slog.Logger) {
	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return // socket closed on shutdown
		}
		tx, ok := stun.IsBindingRequest(buf[:n])
		if !ok {
			continue
		}
		// Report the source address exactly as observed (v4-normalized), which is
		// the node's reflexive address behind its NAT.
		reflexive := netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		if _, err := conn.WriteToUDPAddrPort(stun.BindingResponse(tx, reflexive), from); err != nil && logger != nil {
			logger.Debug("stun: write response failed", "to", from.String(), "err", err)
		}
	}
}
