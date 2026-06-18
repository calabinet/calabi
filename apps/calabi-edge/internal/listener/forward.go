// Peer-forward listener.
//
// This listener binds a VPC-internal port (cfg.mesh.forward_addr, e.g.
// ":7090") and accepts connections from SAME-REGION peer edges. A peer dials
// here when a visitor landed on it but the requested tunnel is owned by THIS
// edge (the peer learned the owner from tunnel-svc.ResolveOwners).
//
// Wire protocol: a mesh.ForwardHeader + sniffed head bytes prefix
// internal/mesh/frame.go), then the raw bidirectional visitor stream. This
// listener does its OWN router lookup on the header's Host — the local router
// is authoritative for which proxy currently serves that name — opens a yamux
// stream to the client, replays the head, and splices.
//
// Bytes are metered on THIS edge's session (the owner), the single source of
// truth for the customer's quota; the relay edge never meters, so traffic is
// never double-counted.
//
// Anti-loop: this listener NEVER re-forwards. On a router miss it returns the
// same response the public listener would (502 for HTTP/HTTPS, silent close
// for SNI) straight back down the peer conn, which the relay pipes to the
// visitor. A frame is therefore served locally or rejected — never relayed
// onward — so no forwarding loop can form even under a split-brain owner
// registry.
//
// Security: bind this ONLY on a VPC-internal interface gated by a security
// group that admits the region's edges. It carries no auth of its own — the
// network boundary is the trust boundary (same model as the cluster-internal
// gRPC ClusterIPs).
package listener

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/calabi/calabi/apps/calabi-edge/internal/mesh"
	"github.com/calabi/calabi/apps/calabi-edge/internal/router"
	"github.com/calabi/calabi/apps/calabi-edge/internal/session"
	proto "github.com/calabi/calabi/pkg/protocol"
)

// forwardReadTimeout caps how long we wait for a peer to send the frame
// prefix after connecting. Generous (the peer assembles + writes it in one
// shot) but bounded so a stray/half-open conn can't pin a goroutine.
const forwardReadTimeout = 15 * time.Second

// ForwardObserver is the metrics surface for the peer-forward listener.
// It reuses the HTTP observer shape; proxy_type is "forward" so relayed
// traffic is distinguishable from directly-served traffic in dashboards.
type ForwardObserver interface {
	OnVisitorRequest(proxyType, outcome string)
	OnBytesTransferred(proxyType, direction string, n int64)
}

// ForwardOptions configures the peer-forward listener.
type ForwardOptions struct {
	Addr     string // VPC-internal bind addr, e.g. ":7090". Empty = disabled.
	Router   *router.Router
	Observer ForwardObserver // may be nil
}

// Forward is the peer-forward listener handle.
type Forward struct {
	opts   ForwardOptions
	logger *slog.Logger

	ln       net.Listener
	stopping atomic.Bool
}

// NewForward builds an unstarted peer-forward listener. Empty Addr yields a
// no-op listener (Run blocks until ctx done) so the goroutine slot in main
// stays uniform whether or not mesh is enabled.
func NewForward(logger *slog.Logger, opts ForwardOptions) *Forward {
	return &Forward{
		opts:   opts,
		logger: logger.With("component", "listener.forward"),
	}
}

// Run blocks until ctx cancels or Listen fails. Empty Addr is a no-op.
func (f *Forward) Run(ctx context.Context) error {
	if f.opts.Addr == "" {
		<-ctx.Done()
		return nil
	}
	ln, err := net.Listen("tcp", f.opts.Addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", f.opts.Addr, err)
	}
	f.ln = ln
	f.logger.Info("peer-forward listener up", "addr", f.opts.Addr)

	go func() {
		<-ctx.Done()
		f.stopping.Store(true)
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if f.stopping.Load() {
				return nil
			}
			f.logger.Warn("accept", "err", err)
			continue
		}
		go f.handle(conn)
	}
}

func (f *Forward) handle(peer net.Conn) {
	defer peer.Close()

	_ = peer.SetReadDeadline(time.Now().Add(forwardReadTimeout))
	br := bufio.NewReaderSize(peer, 8192)
	hdr, head, err := mesh.ReadFrame(br)
	if err != nil {
		f.logger.Debug("frame decode", "err", err, "remote", peer.RemoteAddr())
		f.observeRequest("decode", "frame_failed")
		return
	}
	_ = peer.SetReadDeadline(time.Time{})

	// Route by Host. The local router is authoritative for which proxy
	// currently serves this name. HTTP and HTTPS share the Host-keyed table
	// (the edge terminates TLS for HTTPS before routing); SNI has its own.
	var target router.Target
	var ok bool
	switch hdr.Kind {
	case mesh.KindHTTP, mesh.KindHTTPS:
		target, ok = f.opts.Router.LookupHTTP(hdr.Host)
	case mesh.KindSNI:
		target, ok = f.opts.Router.LookupSNI(hdr.Host)
	default:
		f.observeRequest(hdr.Kind, "bad_kind")
		return
	}
	if !ok {
		// We were told we own this name but no longer do (failover race, or
		// the owner registry the relay used is stale). Mirror the public
		// listener's miss behaviour so the visitor sees a sane response.
		f.logger.Info("forward miss: not owned here",
			"kind", hdr.Kind, "host", hdr.Host, "origin_edge", hdr.OriginEdge)
		if hdr.Kind != mesh.KindSNI {
			writeStatus(peer, 502, fmt.Sprintf("no tunnel for host %q", hdr.Host))
		}
		f.observeRequest(hdr.Kind, "no_tunnel")
		return
	}
	sess, ok := target.Session.(*session.Session)
	if !ok {
		if hdr.Kind != mesh.KindSNI {
			writeStatus(peer, 500, "internal: routing target type mismatch")
		}
		f.observeRequest(hdr.Kind, "internal_error")
		return
	}

	// Security policy (server-authoritative IP allowlist). A mesh-relayed
	// connection reaches the OWNING edge here — enforce with the ORIGINAL
	// visitor IP the relay carries (hdr.VisitorIP), NOT the peer edge's
	// address. Without this, hitting any same-region peer would bypass the
	// owner's IP policy. HTTP/HTTPS → 403; SNI passthrough → silent close.
	if p := sess.Proxy(target.ProxyID); p != nil {
		if pol := p.LoadPolicy(); pol.HasIPRules() && !pol.AllowIPString(hdr.VisitorIP) {
			if hdr.Kind != mesh.KindSNI {
				writeStatus(peer, 403, "forbidden: source IP not allowed")
			}
			f.observeRequest(hdr.Kind, "ip_denied")
			return
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := sess.OpenProxyConn(ctx, &proto.NewConnRequest{
		ProxyID:      target.ProxyID,
		VisitorIP:    hdr.VisitorIP,
		VisitorPort:  hdr.VisitorPort,
		OriginalHost: hdr.Host,
		OriginalPath: hdr.Path,
		InitialBytes: head,
	})
	if err != nil {
		f.logger.Info("forward open upstream",
			"err", err, "kind", hdr.Kind, "host", hdr.Host, "session_id", target.SessionID)
		if hdr.Kind != mesh.KindSNI {
			writeStatus(peer, 502, "upstream unavailable: "+err.Error())
		}
		f.observeRequest(hdr.Kind, "open_upstream_failed")
		return
	}
	defer stream.Close()

	// Replay the sniffed head the relay edge captured (HTTP request head /
	// TLS ClientHello) so the client's local server sees the original bytes.
	if _, err := stream.Write(head); err != nil {
		f.observeRequest(hdr.Kind, "replay_head_failed")
		return
	}
	f.observeRequest(hdr.Kind, "forwarded_ok")
	f.observeBytes("visitor_to_client", int64(len(head)))
	// per-tunnel byte attribution. Metering happens only on the
	// owner edge (this path); the relay edge does not meter, so a
	// forwarded request still bills its tunnel exactly once.
	inC, outC := proxyMeters(sess, target.ProxyID)
	inC.Add(uint64(len(head)))

	f.logger.Info("forwarding",
		"kind", hdr.Kind, "host", hdr.Host,
		"origin_edge", hdr.OriginEdge,
		"session_id", target.SessionID, "proxy_id", target.ProxyID)

	// Splice peer(relay) <-> stream(client). Meter on the owner session
	// through its bandwidth limiter — identical accounting to the direct
	// listeners, so a forwarded request bills the customer exactly once.
	lim := sess.Limiter()
	type result struct {
		dir   string
		bytes int64
		err   error
	}
	errCh := make(chan result, 2)
	go func() {
		n, e := io.Copy(newBytesMeter(lim.Writer(stream), inC), br)
		errCh <- result{"visitor->stream", n, e}
	}()
	go func() {
		n, e := io.Copy(newBytesMeter(lim.Writer(peer), outC), stream)
		errCh <- result{"stream->visitor", n, e}
	}()
	first := <-errCh
	switch first.dir {
	case "visitor->stream":
		f.observeBytes("visitor_to_client", first.bytes)
	case "stream->visitor":
		f.observeBytes("client_to_visitor", first.bytes)
	}
	f.logger.Debug("forward direction finished",
		"dir", first.dir, "bytes", first.bytes, "err", first.err,
		"proxy_id", target.ProxyID)
}

func (f *Forward) observeRequest(kind, outcome string) {
	if f.opts.Observer != nil {
		// Label proxy_type as "forward" so relayed requests are visible
		// separately; fold the real kind into the outcome for granularity.
		f.opts.Observer.OnVisitorRequest("forward", kind+"_"+outcome)
	}
}

func (f *Forward) observeBytes(direction string, n int64) {
	if f.opts.Observer != nil {
		f.opts.Observer.OnBytesTransferred("forward", direction, n)
	}
}
