// Peer-forward relay.
//
// The public HTTP/HTTPS/SNI listeners call relayToPeer in their router-miss
// branch. When a same-region peer edge owns the requested host, we open a
// VPC-internal connection to that peer's forward listener (see forward.go),
// write the mesh frame (header + the head bytes we already sniffed), and
// splice the visitor connection through. The peer edge does the real routing
// and metering.
//
// If no peer owns the host — or the owner is THIS edge, or the owner is
// known-dead, or the dial/frame write fails — relayToPeer returns false and
// the caller falls back to its normal miss response (502 for HTTP/HTTPS,
// silent close for SNI). It NEVER writes to the visitor before a successful
// splice, so the fallback path can always produce a clean response.
package listener

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/calabi/calabi/apps/calabi-edge/internal/mesh"
)

// meshDialTimeout caps how long we wait to connect to the owner edge's
// VPC-internal forward port. Same-region VPC RTT is sub-millisecond, so a
// few seconds is generous; past that the owner is effectively unreachable
// and we fall back to a local miss.
const meshDialTimeout = 5 * time.Second

// OwnerResolver maps a visitor host to the same-region peer edge that owns
// the tunnel, and to that peer's dialable forward addr. It is implemented in
// cmd/calabi-edge by the owner-cache + edge address book; the listeners
// only ever see this narrow read-only interface.
//
// ResolveOwner returns ok=false (caller falls back to a local miss) when:
//   - no known owner for host,
//   - the owner is THIS edge (a genuine local miss — the client likely just
//     dropped; forwarding to ourselves would loop), or
//   - the owner edge is known-dead / has no advertised internal_addr.
type OwnerResolver interface {
	ResolveOwner(host string) (addr string, edgeID int64, ok bool)
}

// ownerRefresher is an OPTIONAL capability a resolver may implement. When a
// forward dial fails (the owner moved or died since the last poll) we kick an
// off-cycle refresh so the next visitor re-resolves to the new owner without
// waiting for the regular poll tick.
type ownerRefresher interface {
	RefreshSoon()
}

// relayToPeer attempts to forward the visitor connection to the owning peer
// edge. Returns true iff it took ownership of the connection (a peer was
// resolved, dialed, framed, and the bidirectional splice ran). Returns false
// — having written NOTHING to the visitor — when the caller should fall back
// to its normal miss response.
//
// br is the buffered reader over visitor; it already holds everything after
// the sniffed `head` (the head is replayed inside the frame by the owner).
func relayToPeer(
	logger *slog.Logger,
	resolver OwnerResolver,
	selfEdgeID int64,
	observer ForwardObserver,
	kind, host, path string,
	visitor net.Conn,
	br *bufio.Reader,
	head []byte,
) bool {
	if resolver == nil {
		return false
	}
	addr, ownerID, ok := resolver.ResolveOwner(host)
	if !ok {
		return false
	}

	peer, err := net.DialTimeout("tcp", addr, meshDialTimeout)
	if err != nil {
		logger.Info("mesh relay: dial owner failed; falling back to local miss",
			"kind", kind, "host", host, "owner_edge", ownerID, "addr", addr, "err", err)
		// The owner we cached is unreachable — re-resolve off-cycle so the
		// next visitor picks up the new owner promptly.
		if rf, ok := resolver.(ownerRefresher); ok {
			rf.RefreshSoon()
		}
		return false
	}
	defer peer.Close()

	hdr := mesh.ForwardHeader{
		Kind:        kind,
		Host:        host,
		Path:        path,
		VisitorIP:   extractIP(visitor.RemoteAddr()),
		VisitorPort: uint32(extractPort(visitor.RemoteAddr())),
		OriginEdge:  selfEdgeID,
	}
	if err := mesh.WriteFrame(peer, hdr, head); err != nil {
		logger.Warn("mesh relay: write frame failed; falling back to local miss",
			"kind", kind, "host", host, "owner_edge", ownerID, "err", err)
		return false
	}

	logger.Info("mesh relay: forwarding to owner",
		"kind", kind, "host", host, "owner_edge", ownerID, "addr", addr)
	if observer != nil {
		observer.OnVisitorRequest("forward_relay", kind+"_relayed")
	}

	// Splice visitor(br) <-> peer. NO session metering here — the owner edge
	// meters on its session, so the customer is billed exactly once. The
	// first side to error/EOF unblocks us; the deferred Closes tear down the
	// other half.
	errCh := make(chan error, 2)
	go func() {
		_, e := io.Copy(peer, br)
		errCh <- e
	}()
	go func() {
		_, e := io.Copy(visitor, peer)
		errCh <- e
	}()
	<-errCh
	return true
}
