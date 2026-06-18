// UDP visitor listener.
//
// One UDP socket per tunnel (bound to the assigned remote_port). Inbound
// datagrams are demultiplexed by (visitor_ip, visitor_port) — each unique
// source opens (or reuses) one yamux stream toward the client. Datagrams
// are length-prefixed onto the stream by the framing in pkg/protocol.
//
// Why per-flow streams (and not one big multiplex):
//   - the existing OpenProxyConn / 8-byte preamble pairing model already
//     pairs streams to NEW_CONN; we get free e2e backpressure
//   - source-NAT happens trivially: the conntrack table is the truth
//     about which UDPAddr opened which stream
//   - idle GC is just "close the stream when nothing has moved in 60s"
//     and the client side observes EOF + tears down the local UDP socket
//
// Limits:
//   - max 10k concurrent conntrack entries / listener (configurable);
//     LRU evict when full
//   - 60s default idle reap; on every datagram the deadline is bumped
//   - max datagram is pkg/protocol.MaxUDPDatagram (65535) — anything
//     larger is silently dropped (UDP semantics)
package listener

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/calabi/calabi/apps/calabi-edge/internal/ratelimit"
	"github.com/calabi/calabi/apps/calabi-edge/internal/session"
	proto "github.com/calabi/calabi/pkg/protocol"
)

const (
	// udpReadBuf is the largest datagram the visitor-side socket will
	// surface. Anything larger gets truncated by the OS — we then drop it.
	udpReadBuf = 65 * 1024

	// udpIdleTimeout is how long a conntrack flow may sit unused before
	// the reaper closes its stream + drops the entry.
	udpIdleTimeout = 60 * time.Second

	// udpReapInterval is how often the reaper goroutine scans the table.
	// Cheap to do because the table is small in steady state.
	udpReapInterval = 5 * time.Second

	// udpMaxFlows caps the conntrack table. New flows past this limit
	// evict the LRU entry — this is fail-open, not fail-closed.
	udpMaxFlows = 10_000
)

// UDPObserver is the visitor-facing metrics surface for the UDP listener.
//
// proxyType is always "udp" for this listener but the parameter is kept
// so a single observer impl works across http/tcp/udp.
type UDPObserver interface {
	OnVisitorRequest(proxyType, outcome string)
	OnBytesTransferred(proxyType, direction string, n int64)
}

// StartUDPProxy opens a UDP socket on remotePort, returns an io.Closer
// that owns both the socket and the reaper goroutine. Closing it stops
// the conntrack reaper and forces every active flow to tear down.
//
// remotePort 0 returns an error: UDP has no "let the OS pick" semantics
// from this layer's perspective (the proto handshake assigns a port up
// front).
func StartUDPProxy(logger *slog.Logger, remotePort uint32, sess *session.Session, proxyID string, obs UDPObserver, glob *ratelimit.GlobalLimiter) (io.Closer, error) {
	if remotePort == 0 {
		return nil, errors.New("listener.udp: remote_port must be non-zero")
	}
	addr := fmt.Sprintf(":%d", remotePort)
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen udp %s: %w", addr, err)
	}
	udpLog := logger.With(
		"component", "listener.udp",
		"proxy_id", proxyID,
		"remote_port", remotePort,
	)
	udpLog.Info("udp proxy listening")

	u := &udpProxy{
		logger:  udpLog,
		conn:    pc,
		sess:    sess,
		proxyID: proxyID,
		obs:     obs,
		glob:    glob,
		flows:   make(map[string]*udpFlow),
		lru:     list.New(),
		stopCh:  make(chan struct{}),
	}
	go u.acceptLoop()
	go u.reapLoop()
	return u, nil
}

// udpFlow is one conntrack entry: a single (visitor_ip, visitor_port)
// mapped onto one yamux stream toward the client.
type udpFlow struct {
	stream   io.ReadWriteCloser
	visitor  net.Addr
	lastSeen atomic.Int64 // unix nanos
	lruEl    *list.Element

	// release returns this flow's slot to the org's concurrent-connection
	// limiter (Phase A anti-abuse). Set when the flow is admitted; called
	// exactly once on teardown (closeFlowLocked). nil for unguarded
	// sessions / LRU-evicted-before-admit edge cases.
	release func()

	// closed guards the teardown so reapLoop and the stream-reader
	// goroutine don't race on stream.Close().
	closed atomic.Bool
}

type udpProxy struct {
	logger  *slog.Logger
	conn    net.PacketConn
	sess    *session.Session
	proxyID string
	obs     UDPObserver
	glob    *ratelimit.GlobalLimiter // process-wide backpressure (Phase B); nil = unlimited

	mu    sync.Mutex
	flows map[string]*udpFlow // key = visitor.String()
	lru   *list.List          // *udpFlow ordered LRU (front = most recent)

	stopCh   chan struct{}
	stopOnce sync.Once
}

// Close stops the listener; idempotent.
func (u *udpProxy) Close() error {
	u.stopOnce.Do(func() {
		close(u.stopCh)
		_ = u.conn.Close()
		u.mu.Lock()
		for _, f := range u.flows {
			u.closeFlowLocked(f)
		}
		u.flows = map[string]*udpFlow{}
		u.lru.Init()
		u.mu.Unlock()
	})
	return nil
}

func (u *udpProxy) acceptLoop() {
	buf := make([]byte, udpReadBuf)
	for {
		n, src, err := u.conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				u.logger.Info("udp proxy stopped")
				return
			}
			u.logger.Warn("udp read", "err", err)
			// Persistent socket-level errors back off lightly.
			time.Sleep(20 * time.Millisecond)
			continue
		}
		// Copy out — buf is reused next iteration.
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		u.handleDatagram(src, pkt)
	}
}

func (u *udpProxy) handleDatagram(src net.Addr, pkt []byte) {
	if len(pkt) > proto.MaxUDPDatagram {
		if u.obs != nil {
			u.obs.OnVisitorRequest("udp", "oversize_dropped")
		}
		return
	}
	key := src.String()

	u.mu.Lock()
	flow, ok := u.flows[key]
	if ok {
		u.lru.MoveToFront(flow.lruEl)
	}
	u.mu.Unlock()

	if !ok {
		// Security policy (server-authoritative IP allowlist): drop datagrams
		// from a source the tunnel owner hasn't permitted, before opening a
		// flow. Checked once per new flow — the source is fixed for its life.
		if p := u.sess.Proxy(u.proxyID); p != nil {
			if pol := p.LoadPolicy(); pol != nil {
				if pol.HasIPRules() {
					host, _ := splitUDPAddr(src)
					if !pol.AllowIPString(host) {
						if u.obs != nil {
							u.obs.OnVisitorRequest("udp", "ip_denied")
						}
						return
					}
				}
				if pol.HasRateLimit() && !pol.AllowRate() {
					if u.obs != nil {
						u.obs.OnVisitorRequest("udp", "rate_limited")
					}
					return
				}
			}
		}
		// First datagram from this visitor = a new "connection" for
		// anti-abuse accounting. Gate machine-wide (Phase B) FIRST, then
		// per-org (Phase A): TCP/TLS new-connection rate, then a concurrent
		// slot. Unconfigured limiters / unguarded sessions pass through.
		grel, shed := globalAdmit(u.glob)
		if shed != "" {
			if u.obs != nil {
				u.obs.OnVisitorRequest("udp", shed)
			}
			return
		}
		if rerr := u.sess.AllowTCPConn(); rerr != nil {
			grel()
			if u.obs != nil {
				u.obs.OnVisitorRequest("udp", "rate_limited")
			}
			return
		}
		// Per-day connection cap (daily_tcp_conns). Only free is finite today.
		if rerr := u.sess.AllowTCPConnDaily(); rerr != nil {
			grel()
			if u.obs != nil {
				u.obs.OnVisitorRequest("udp", "daily_capped")
			}
			return
		}
		orel, aerr := u.sess.AcquireConn()
		if aerr != nil {
			grel()
			if u.obs != nil {
				u.obs.OnVisitorRequest("udp", "conn_capped")
			}
			return
		}
		// Combined teardown: return both the per-org and global slots.
		release := func() {
			orel()
			grel()
		}
		// First datagram from this visitor: open a fresh stream and
		// install the conntrack entry. The stream's "downstream"
		// goroutine pumps client→visitor.
		newFlow, err := u.openFlow(src, release)
		if err != nil {
			release() // roll back the reserved slots
			u.logger.Info("open udp flow",
				"err", err, "visitor", src.String())
			if u.obs != nil {
				u.obs.OnVisitorRequest("udp", "open_upstream_failed")
			}
			return
		}
		flow = newFlow
		if u.obs != nil {
			u.obs.OnVisitorRequest("udp", "ok")
		}
	}

	flow.lastSeen.Store(time.Now().UnixNano())
	if err := proto.WriteUDPDatagram(flow.stream, pkt); err != nil {
		u.logger.Debug("udp write to stream",
			"err", err, "visitor", src.String())
		u.dropFlow(key)
		return
	}
	if u.obs != nil {
		u.obs.OnBytesTransferred("udp", "visitor_to_client", int64(len(pkt)))
	}
}

func (u *udpProxy) openFlow(src net.Addr, release func()) (*udpFlow, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	host, port := splitUDPAddr(src)
	stream, err := u.sess.OpenProxyConn(ctx, &proto.NewConnRequest{
		ProxyID:     u.proxyID,
		VisitorIP:   host,
		VisitorPort: port,
	})
	if err != nil {
		return nil, err
	}
	flow := &udpFlow{
		stream:  stream,
		visitor: src,
		release: release,
	}
	flow.lastSeen.Store(time.Now().UnixNano())

	u.mu.Lock()
	// Enforce conntrack cap with LRU eviction.
	if len(u.flows) >= udpMaxFlows {
		oldest := u.lru.Back()
		if oldest != nil {
			victim := oldest.Value.(*udpFlow)
			delete(u.flows, victim.visitor.String())
			u.lru.Remove(oldest)
			u.closeFlowLocked(victim)
		}
	}
	flow.lruEl = u.lru.PushFront(flow)
	u.flows[src.String()] = flow
	u.mu.Unlock()

	go u.streamToVisitor(flow)
	return flow, nil
}

// streamToVisitor reads framed datagrams from the client stream and
// sendto's them back to the original visitor address.
func (u *udpProxy) streamToVisitor(flow *udpFlow) {
	for {
		pkt, err := proto.ReadUDPDatagram(flow.stream)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				u.logger.Debug("read udp from stream",
					"err", err, "visitor", flow.visitor.String())
			}
			u.dropFlow(flow.visitor.String())
			return
		}
		if len(pkt) == 0 {
			continue // keep-alive
		}
		flow.lastSeen.Store(time.Now().UnixNano())
		if _, err := u.conn.WriteTo(pkt, flow.visitor); err != nil {
			u.logger.Debug("udp sendto visitor",
				"err", err, "visitor", flow.visitor.String())
			u.dropFlow(flow.visitor.String())
			return
		}
		if u.obs != nil {
			u.obs.OnBytesTransferred("udp", "client_to_visitor", int64(len(pkt)))
		}
	}
}

func (u *udpProxy) dropFlow(key string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	flow, ok := u.flows[key]
	if !ok {
		return
	}
	delete(u.flows, key)
	if flow.lruEl != nil {
		u.lru.Remove(flow.lruEl)
		flow.lruEl = nil
	}
	u.closeFlowLocked(flow)
}

// closeFlowLocked must be called with u.mu held.
func (u *udpProxy) closeFlowLocked(flow *udpFlow) {
	if flow.closed.CompareAndSwap(false, true) {
		_ = flow.stream.Close()
		// Return the concurrent-connection slot exactly once (CAS above
		// guarantees single teardown). nil for unguarded sessions.
		if flow.release != nil {
			flow.release()
		}
	}
}

func (u *udpProxy) reapLoop() {
	t := time.NewTicker(udpReapInterval)
	defer t.Stop()
	for {
		select {
		case <-u.stopCh:
			return
		case <-t.C:
			u.reapOnce()
		}
	}
}

func (u *udpProxy) reapOnce() {
	cutoff := time.Now().Add(-udpIdleTimeout).UnixNano()
	u.mu.Lock()
	defer u.mu.Unlock()
	// Walk LRU from the back (oldest first); stop at the first non-expired
	// entry since the LRU keeps lastSeen monotonic in expectation.
	for el := u.lru.Back(); el != nil; {
		prev := el.Prev()
		flow := el.Value.(*udpFlow)
		if flow.lastSeen.Load() > cutoff {
			// LRU order isn't strict (handleDatagram only re-orders on
			// table hit, not every read), so don't break — keep going
			// to the next entry. Cheap because the table is small.
			el = prev
			continue
		}
		delete(u.flows, flow.visitor.String())
		u.lru.Remove(el)
		u.closeFlowLocked(flow)
		el = prev
	}
}

// activeFlows is exposed for tests / debug.
func (u *udpProxy) activeFlows() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.flows)
}

// splitUDPAddr pulls IP + port out of a net.Addr that we already know is
// a *net.UDPAddr in 99% of cases. Falls back to a generic SplitHostPort
// for the long tail.
func splitUDPAddr(a net.Addr) (string, uint32) {
	if u, ok := a.(*net.UDPAddr); ok {
		return u.IP.String(), uint32(u.Port)
	}
	host, portStr, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String(), 0
	}
	var p int
	fmt.Sscanf(portStr, "%d", &p)
	return host, uint32(p)
}
