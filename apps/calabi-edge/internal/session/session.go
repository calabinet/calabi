// Package session models a single client connection to the edge node.
//
// Lifecycle:
//
//	(yamux up) -> Hello -> Auth -> Established -> ... -> Draining -> Closed
//
// Each Session owns one yamux session, one control stream, a registry of
// proxies the client has opened, and a stream-acceptor goroutine that
// matches inbound data streams to outstanding NEW_CONN requests.
package session

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/calabinet/calabi/apps/calabi-edge/internal/policy"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/ratelimit"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	proto "github.com/calabinet/calabi/pkg/protocol"
)

// streamPreambleTimeout caps how long we wait for the client to write the
// 8-byte stream-id preamble after opening a data stream.
const streamPreambleTimeout = 5 * time.Second

// Proxy is one tunnel the client has registered.
//
// Listener is non-nil for TCP/UDP proxies — it owns the OS-level socket
// accepting visitor connections. Closing it stops the accept loop and is
// part of the proxy teardown ritual (see controlloop.go).
//
// TunnelID is the row id assigned by tunnel-svc when the edge persists
// the registration; 0 means the edge is running standalone (no control
// plane wired up) or the persist call failed (best-effort).
type Proxy struct {
	ID         string
	Type       proto.ProxyKind
	Domain     string
	RemotePort uint32
	LocalAddr  string
	Name       string
	Listener   io.Closer
	TunnelID   int64

	// ClaimTunnelID, when non-zero, signals that this NEW_PROXY is the
	// client's claim on an already-existing tunnel-svc row (created by
	// the console with edge_node_id=0 — see Phase D). The persister uses
	// this to update the existing row in place instead of inserting a
	// duplicate. After OnProxyOpened succeeds, TunnelID is set to the
	// same value (claimed rows are addressable by the same id afterwards).
	ClaimTunnelID int64

	// ProposedSecurityJSON is the security block the CLIENT sent in NEW_PROXY
	// options (`calabi http 8080 --ip-allow …`). UNTRUSTED and never applied
	// here on a managed edge — it is relayed to the control plane, which keeps
	// only the IP lists and revalidates them.
	//
	// Carried on the Proxy rather than applied where it arrives because the two
	// uses are different: a STANDALONE edge applies it directly (there is no
	// control plane to ask), while a managed edge must hand it to the persister
	// and take back whatever the server decides. It used to be read only on the
	// standalone branch, which is why the flag silently did nothing on the
	// platform — it reached the edge and stopped there.
	ProposedSecurityJSON string

	// secPolicy holds the server-authoritative security policy for this tunnel
	// (IP allowlist, …), parsed from the tunnel row's config_json — NOT from
	// the daemon's NEW_PROXY options. It is SWAPPABLE at runtime: the persister
	// sets it at registration, and the config-svc delta applier hot-swaps it on
	// a console/SPA edit so changes take effect without a reconnect. Atomic so
	// listeners (readers, every visitor accept) never race the swap. A nil load
	// = no policy (allow all). Use SetPolicy / LoadPolicy. See internal/policy.
	secPolicy atomic.Pointer[policy.Policy]

	// lim is THIS tunnel's bandwidth bucket (the lower of the two tiers —
	// the org-wide one lives on the Session). Built by RegisterProxy from the
	// session's per-tunnel rates; nil = unlimited, which is what a
	// struct-literal Proxy in a test gets.
	lim atomic.Pointer[ratelimit.Limiter]

	BytesIn  atomic.Uint64
	BytesOut atomic.Uint64
}

// limiter returns this tunnel's own bucket (nil = unlimited).
func (p *Proxy) limiter() *ratelimit.Limiter {
	if p == nil {
		return nil
	}
	return p.lim.Load()
}

// SetBandwidthLimit rebuilds this tunnel's own bucket. Used by the config
// hot-update path; RegisterProxy calls it once at registration.
func (p *Proxy) SetBandwidthLimit(sustainedBps, peakBps int64) {
	if p == nil {
		return
	}
	if sustainedBps <= 0 {
		p.lim.Store(nil)
		return
	}
	p.lim.Store(ratelimit.New(sustainedBps, peakBps))
}

// SetPolicy atomically installs (or clears, with nil) this proxy's security
// policy. Called by the persister at registration and by the config-svc delta
// applier on a live edit.
func (p *Proxy) SetPolicy(pol *policy.Policy) { p.secPolicy.Store(pol) }

// LoadPolicy returns the current security policy (nil = allow all). Listeners
// call this once per visitor accept; the returned *Policy's methods are
// nil-safe so callers don't need a nil guard.
func (p *Proxy) LoadPolicy() *policy.Policy { return p.secPolicy.Load() }

// pendingConn captures a waiter for OpenProxyConn.
type pendingConn struct {
	streamCh chan io.ReadWriteCloser
	errCh    chan error
}

// Session is a live client session.
type Session struct {
	ID          string
	TenantID    string
	WorkspaceID string
	ClientID    string
	// DeviceID is the identity-svc clients.id the client announced in
	// its AUTH frame. 0 = unknown. Used
	// for live-presence reporting to identity-svc (Phase A); not a
	// security boundary — the bearer token in AUTH is authoritative.
	DeviceID int64

	// ConnEpoch is this connection's monotonic epoch: the edge's
	// wall-clock unix-millis captured at session birth (New). Reported
	// with each presence tick so identity-svc can tell a fresh re-home
	// (larger epoch) from a stale straggler (smaller epoch) and refuse
	// to let an old edge that hasn't reaped a dead session steal the
	// presence row back. See ReportClientPresence in identity-svc.
	ConnEpoch int64

	// TrustClientPolicy, when true (standalone / self-hosted edge), makes
	// handleNewProxy apply the per-proxy security policy the client supplies in
	// NEW_PROXY (ProxyOptions.security_config_json). Default false (managed
	// multi-tenant edge) ignores client-supplied policy — security then comes
	// only from the server-authoritative config_json. Set once at session
	// creation from ControlOptions.TrustClientPolicy.
	TrustClientPolicy bool

	// grants is set when this session authenticated by a coordinator grant
	// (grantauth.go): grantNode is the node key it proved, and grantExpiry,
	// under mu, is when it must have presented a newer grant.
	grants      GrantAuth
	grantNode   meshproto.NodeKey
	grantExpiry time.Time

	logger *slog.Logger
	mux    *yamux.Session
	ctrl   *frameStream

	mu      sync.Mutex
	proxies map[string]*Proxy
	pending map[uint64]*pendingConn
	// conns tracks live visitor data streams per proxy id so a proxy
	// teardown (CLOSE_PROXY / disable / config push) can force-close the
	// in-flight connections, not just stop new lookups. Without this, an
	// already-spliced keep-alive visitor connection would keep flowing on
	// its open yamux stream after the route is gone. mu-guarded.
	conns map[string]map[*trackedConn]struct{}

	nextStreamID atomic.Uint64

	// Bandwidth limiting is TWO tiers:
	//
	//   - tunnelSustained / tunnelPeak are the PER-TUNNEL rates. Each Proxy
	//     gets its own bucket built from them at RegisterProxy time, so two
	//     tunnels on one session no longer share one bucket the way the old
	//     per-session limiter made them.
	//   - orgLimiter is the org-wide bucket, SHARED with every other session
	//     of the same org on this edge (ratelimit.OrgRegistry owns it). nil =
	//     no org tier (unresolvable tenant, or quota not wired).
	//
	// Every byte clears both. See ratelimit.Chain.
	tunnelSustained atomic.Int64
	tunnelPeak      atomic.Int64
	orgLimiter      atomic.Pointer[ratelimit.Limiter]

	// connGuard holds the per-org connection limiters (Phase A anti-abuse,
	// 2026-06-11): concurrent-connection cap + new-connection rate gates.
	// nil (the zero value) = no connection limiting for this session
	// (dev / standalone / static-token tenants). Installed at handshake
	// once quota-svc has been consulted. See ConnGuard.
	connGuard atomic.Pointer[ConnGuard]

	// Byte counters accumulated by listener forwarding paths. Read by
	// the usage reporter on a 60s cadence to publish to
	// NATS calabi.usage.report. Atomic so listeners don't have to lock.
	BytesIn  atomic.Uint64 // visitor → tunnel (uploads)
	BytesOut atomic.Uint64 // tunnel → visitor (downloads)

	// blockReason, when non-empty, causes OpenProxyConn to fail fast.
	// Set by the usage.DenyHook bridge when NATS announces this org is
	// over monthly_traffic_mb. In-flight conns continue serving.
	blockReason atomic.Pointer[string]

	closed   atomic.Bool
	closedCh chan struct{}
	acceptCh chan struct{} // closed when acceptStreams exits
}

// New wraps an established yamux session whose first stream is the control
// stream.
func New(logger *slog.Logger, mux *yamux.Session, ctrl io.ReadWriteCloser) *Session {
	s := &Session{
		logger:    logger,
		mux:       mux,
		ctrl:      newFrameStream(ctrl),
		proxies:   make(map[string]*Proxy),
		pending:   make(map[uint64]*pendingConn),
		conns:     make(map[string]map[*trackedConn]struct{}),
		closedCh:  make(chan struct{}),
		acceptCh:  make(chan struct{}),
		ConnEpoch: time.Now().UnixMilli(),
	}
	return s // both tiers start unset = unlimited
}

// SetBandwidthLimit installs the PER-TUNNEL dual-rate cap (套餐「带宽速度 /
// 带宽上限」). sustainedBps=0 == unlimited; peakBps>sustainedBps adds a burst
// ceiling.
//
// It takes effect for tunnels registered AFTER it — which is every tunnel in
// practice, because the handshake resolves quota before the client is allowed
// to open a proxy. Tunnels already open keep the bucket they were built with;
// re-rating those live is the hot-update path and is not wired yet (same as
// before this change).
func (s *Session) SetBandwidthLimit(sustainedBps, peakBps int64) {
	s.tunnelSustained.Store(sustainedBps)
	s.tunnelPeak.Store(peakBps)
}

// SetOrgLimiter installs the org-wide tier, shared with the org's other
// sessions on this edge. nil clears it (no org tier).
func (s *Session) SetOrgLimiter(l *ratelimit.Limiter) { s.orgLimiter.Store(l) }

// OrgLimiter returns the org-wide tier, or nil when there is none.
func (s *Session) OrgLimiter() *ratelimit.Limiter { return s.orgLimiter.Load() }

// LimiterFor returns the two-tier limiter for one tunnel: that tunnel's own
// bucket plus the org-wide one. Never nil, so listeners can wrap without
// checking; an unknown proxy id (a connection that raced the proxy's teardown)
// still gets the org tier, which is the safe side to err on.
func (s *Session) LimiterFor(proxyID string) *ratelimit.Chain {
	org := s.orgLimiter.Load()
	s.mu.Lock()
	p := s.proxies[proxyID]
	s.mu.Unlock()
	if p == nil {
		return ratelimit.NewChain(nil, org)
	}
	return ratelimit.NewChain(p.limiter(), org)
}

// ConnGuard bundles the process-global per-org connection limiters with
// this session's resolved org_id. Installed at handshake (control.go) by
// the ConnGuardInstaller once quota-svc has been consulted. The limiters
// are shared pointers across every session of the same org, so concurrent
// counts and rate buckets aggregate correctly for a customer running
// multiple client devices. A nil ConnGuard disables connection limiting
// for that session.
type ConnGuard struct {
	OrgID    int64
	Conns    *ratelimit.ConnLimiter // concurrent-connection cap (max_conns)
	HTTPRate *ratelimit.RateLimiter // new HTTP(S) connection rate (http_conn_rate_per_min)
	TCPRate  *ratelimit.RateLimiter // new TCP/TLS(+SNI/UDP-flow) rate (tcp_conn_rate_per_min)
	// Per-day cumulative caps (2026-06-12). TCPDaily counts new TCP/TLS/UDP
	// connections; HTTPDaily counts HTTP/HTTPS *requests* (fed by the
	// listener's request-boundary parser). Both nil = no daily cap.
	TCPDaily  *ratelimit.DailyCounter // daily_tcp_conns
	HTTPDaily *ratelimit.DailyCounter // daily_http_reqs
}

// SetConnGuard installs (or replaces) this session's connection guard.
// Safe to call concurrently with the Acquire/Allow accessors.
func (s *Session) SetConnGuard(g *ConnGuard) { s.connGuard.Store(g) }

// AcquireConn reserves one slot against the org's concurrent-connection
// cap (max_conns). The returned release is ALWAYS non-nil on success
// (including the no-guard / unlimited paths) so callers can `defer
// release()` once they've confirmed err == nil. On the cap-hit path it
// returns (nil, ratelimit.ErrConnLimitExceeded) — check err before
// deferring. Counts aggregate across every session of the same org.
func (s *Session) AcquireConn() (release func(), err error) {
	g := s.connGuard.Load()
	if g == nil || g.Conns == nil {
		return func() {}, nil
	}
	return g.Conns.Acquire(g.OrgID)
}

// AllowHTTPConn consumes one token from the org's HTTP(S) new-connection
// rate bucket (http_conn_rate_per_min). Returns
// ratelimit.ErrRateLimitExceeded when drained; nil when allowed or
// unguarded. Used by the HTTP + HTTPS (TLS-terminated) listeners.
func (s *Session) AllowHTTPConn() error {
	g := s.connGuard.Load()
	if g == nil || g.HTTPRate == nil {
		return nil
	}
	return g.HTTPRate.Allow(g.OrgID)
}

// AllowTCPConn consumes one token from the org's TCP/TLS new-connection
// rate bucket (tcp_conn_rate_per_min). Used by the raw-TCP listener, the
// SNI passthrough listener, and per-new-flow on the UDP listener.
func (s *Session) AllowTCPConn() error {
	g := s.connGuard.Load()
	if g == nil || g.TCPRate == nil {
		return nil
	}
	return g.TCPRate.Allow(g.OrgID)
}

// AllowTCPConnDaily records one new TCP/TLS(+SNI/UDP-flow) connection against
// the org's per-day cap (daily_tcp_conns). Returns
// ratelimit.ErrDailyLimitExceeded once the day's budget is spent; nil when
// under cap or unguarded. Used by the raw-TCP / SNI / UDP listeners.
func (s *Session) AllowTCPConnDaily() error {
	g := s.connGuard.Load()
	if g == nil || g.TCPDaily == nil {
		return nil
	}
	return g.TCPDaily.Allow(g.OrgID)
}

// AllowHTTPReq records one HTTP/HTTPS REQUEST against the org's per-day cap
// (daily_http_reqs). Returns ratelimit.ErrDailyLimitExceeded once the day's
// budget is spent; nil when under cap or unguarded. Called once per sniffed
// first request and then once per subsequent request by the HTTP/HTTPS
// listeners' request-boundary counter.
func (s *Session) AllowHTTPReq() error {
	g := s.connGuard.Load()
	if g == nil || g.HTTPDaily == nil {
		return nil
	}
	return g.HTTPDaily.Allow(g.OrgID)
}

// Logger returns the session's structured logger.
func (s *Session) Logger() *slog.Logger { return s.logger }

// Done returns a channel that is closed when the session ends.
func (s *Session) Done() <-chan struct{} { return s.closedCh }

// Close terminates the session and unblocks pending waiters.
func (s *Session) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(s.closedCh)
	s.mu.Lock()
	for sid, pc := range s.pending {
		select {
		case pc.errCh <- errors.New("session closed"):
		default:
		}
		delete(s.pending, sid)
	}
	s.mu.Unlock()
	_ = s.ctrl.Close()
	return s.mux.Close()
}

// RegisterProxy adds p; returns false on duplicate ID.
func (s *Session) RegisterProxy(p *Proxy) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.proxies == nil {
		// Defensive: New() always initialises this, but struct-literal
		// sessions (used in unit tests) start with a nil map.
		s.proxies = make(map[string]*Proxy)
	}
	if _, ok := s.proxies[p.ID]; ok {
		return false
	}
	// Give the tunnel its own bucket from the session's per-tunnel rates.
	// Done here rather than at the call sites so every path that registers a
	// proxy (client NEW_PROXY, standalone YAML, tests) gets it — a tunnel that
	// slipped in without a bucket would be silently unlimited, which is the
	// failure mode two-tier limiting exists to close.
	p.SetBandwidthLimit(s.tunnelSustained.Load(), s.tunnelPeak.Load())
	s.proxies[p.ID] = p
	return true
}

// UnregisterProxy removes a proxy from this session's proxy table.
// Used by handleNewProxy's rollback path: if persister.OnProxyOpened
// returns an error (port collision detected at DB level), we tear the
// freshly-registered proxy back out so it can't take traffic and so the
// session-end defer doesn't try to OnProxyClosed it.
func (s *Session) UnregisterProxy(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.proxies, id)
}

// OrgID returns the numeric org this session belongs to, or 0 when it cannot
// be determined (a dev / static-YAML tenant whose id is not a number).
//
// Two sources, in order: the ConnGuard installed at handshake carries an org
// already resolved by quota-svc, and TenantID is the raw handshake value. They
// agree whenever both exist; the guard is preferred because a session without
// quota wiring still has the string.
func (s *Session) OrgID() int64 {
	if g := s.connGuard.Load(); g != nil && g.OrgID > 0 {
		return g.OrgID
	}
	n, err := strconv.ParseInt(s.TenantID, 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

// Proxy returns a registered proxy or nil.
func (s *Session) Proxy(id string) *Proxy {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.proxies[id]
}

// Proxies returns a snapshot of registered proxies.
func (s *Session) Proxies() []*Proxy {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Proxy, 0, len(s.proxies))
	for _, p := range s.proxies {
		out = append(out, p)
	}
	return out
}

// BlockReason, when non-empty, causes every new OpenProxyConn to fail
// fast (in-flight visitor connections keep serving). Hot-set by the
// usage.DenyHook via SetBlockReason.
//
// Stored as atomic.Pointer[string] so the read path stays lock-free.
var _ = "" // placeholder anchor for the comment above; doc on the field below.

// SetBlockReason marks this session as hard-denied; reason is included
// in the OpenProxyConn error. Empty string clears the block.
func (s *Session) SetBlockReason(reason string) {
	cp := reason
	s.blockReason.Store(&cp)
}

// IsBlocked returns (true, reason) if SetBlockReason was called with
// a non-empty reason and not since cleared.
func (s *Session) IsBlocked() (bool, string) {
	p := s.blockReason.Load()
	if p == nil || *p == "" {
		return false, ""
	}
	return true, *p
}

// OpenProxyConn announces a new visitor connection to the client and waits
// for the matching data stream to arrive (paired by stream_id preamble).
func (s *Session) OpenProxyConn(ctx context.Context, req *proto.NewConnRequest) (io.ReadWriteCloser, error) {
	if s.closed.Load() {
		return nil, errors.New("session closed")
	}
	if blocked, reason := s.IsBlocked(); blocked {
		return nil, fmt.Errorf("session blocked: %s", reason)
	}
	if req.StreamID == 0 {
		req.StreamID = s.nextStreamID.Add(1)
	}

	pc := &pendingConn{
		streamCh: make(chan io.ReadWriteCloser, 1),
		errCh:    make(chan error, 1),
	}
	s.mu.Lock()
	s.pending[req.StreamID] = pc
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pending, req.StreamID)
		s.mu.Unlock()
	}()

	if err := s.SendControl(proto.FrameNewConn, req); err != nil {
		return nil, fmt.Errorf("send NEW_CONN: %w", err)
	}

	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, errors.New("timeout waiting for data stream")
	case <-s.closedCh:
		return nil, errors.New("session closed")
	case err := <-pc.errCh:
		return nil, err
	case stream := <-pc.streamCh:
		// Track the stream against its proxy so CloseProxyConns can drop it
		// when the route is torn down. The returned wrapper deregisters
		// itself on normal Close (end of splice).
		tc := &trackedConn{ReadWriteCloser: stream, s: s, proxyID: req.ProxyID, visitorIP: req.VisitorIP}
		s.trackConn(req.ProxyID, tc)
		return tc, nil
	}
}

// trackedConn wraps a data stream handed to a listener so the session can
// force-close it when the proxy's route is removed (CloseProxyConns).
// Close is idempotent on the underlying stream.
type trackedConn struct {
	io.ReadWriteCloser
	s       *Session
	proxyID string
	// visitorIP is the source IP that opened this connection (from the
	// NewConnRequest). Lets a hot policy update cut only the connections a new
	// denylist entry now forbids — established keep-alive conns included —
	// without disturbing still-allowed ones. See CloseProxyConnsDenied.
	visitorIP string
	once      sync.Once
	closErr   error
}

// Close is the listener-initiated path (splice ended): stop tracking, then
// close the underlying stream.
func (t *trackedConn) Close() error {
	t.s.untrackConn(t.proxyID, t)
	return t.closeOnce()
}

func (t *trackedConn) closeOnce() error {
	t.once.Do(func() { t.closErr = t.ReadWriteCloser.Close() })
	return t.closErr
}

func (s *Session) trackConn(proxyID string, c *trackedConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conns == nil {
		s.conns = make(map[string]map[*trackedConn]struct{})
	}
	m := s.conns[proxyID]
	if m == nil {
		m = make(map[*trackedConn]struct{})
		s.conns[proxyID] = m
	}
	m[c] = struct{}{}
}

func (s *Session) untrackConn(proxyID string, c *trackedConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m := s.conns[proxyID]; m != nil {
		delete(m, c)
		if len(m) == 0 {
			delete(s.conns, proxyID)
		}
	}
}

// CloseProxyConns force-closes every in-flight visitor connection still
// riding proxyID and returns how many it closed. Called when the proxy's
// route is removed (disable / CLOSE_PROXY / config push) so existing
// keep-alive connections stop immediately — not just new lookups.
//
// Closing happens outside s.mu (it touches the network); the conns are
// snapshotted and detached under the lock first.
func (s *Session) CloseProxyConns(proxyID string) int {
	s.mu.Lock()
	m := s.conns[proxyID]
	delete(s.conns, proxyID)
	list := make([]*trackedConn, 0, len(m))
	for c := range m {
		list = append(list, c)
	}
	s.mu.Unlock()
	for _, c := range list {
		_ = c.closeOnce()
	}
	return len(list)
}

// CloseProxyConnsDenied force-closes in-flight visitor connections on proxyID
// whose source IP the (just-updated) policy now DENIES, and returns how many it
// cut. This is what makes a new denylist entry take effect on ESTABLISHED
// keep-alive connections immediately: the per-connection IP check only gates
// NEW connections, but a browser holds its connection open, so without this the
// user would have to restart it. Connections the policy still allows are left
// untouched. A nil / rule-less policy closes nothing.
//
// Mirrors CloseProxyConns' locking: snapshot the doomed conns under s.mu, then
// closeOnce() them outside the lock (Close touches the network); each closed
// conn deregisters itself via its splice's trackedConn.Close → untrackConn.
func (s *Session) CloseProxyConnsDenied(proxyID string, pol *policy.Policy) int {
	if !pol.HasIPRules() {
		return 0
	}
	s.mu.Lock()
	var list []*trackedConn
	for c := range s.conns[proxyID] {
		if !pol.AllowIPString(c.visitorIP) {
			list = append(list, c)
		}
	}
	s.mu.Unlock()
	for _, c := range list {
		_ = c.closeOnce()
	}
	return len(list)
}

// HandleConnAck logs the ack. it is advisory; pairing happens via the
// 8-byte preamble on the data stream.
func (s *Session) HandleConnAck(ack *proto.ConnAck) {
	if ack.Error != nil {
		s.logger.Info("client reported local dial failure",
			"stream_id", ack.StreamID,
			"err", ack.Error.MessageEN,
		)
		s.mu.Lock()
		pc, ok := s.pending[ack.StreamID]
		s.mu.Unlock()
		if ok {
			select {
			case pc.errCh <- ack.Error:
			default:
			}
		}
	}
}

// SendControl is a thin wrapper over the control stream's frame writer.
func (s *Session) SendControl(t proto.FrameType, payload any) error {
	return s.ctrl.WritePayload(t, payload)
}

// ReadFrame returns the next frame from the control stream.
func (s *Session) ReadFrame() (proto.Frame, error) {
	return s.ctrl.Read()
}

// StartStreamAcceptor launches the background goroutine that accepts data
// streams from the yamux session and pairs them by stream-id preamble.
//
// Safe to call once per Session.
func (s *Session) StartStreamAcceptor() {
	go s.acceptStreams()
}

func (s *Session) acceptStreams() {
	defer close(s.acceptCh)
	for {
		stream, err := s.mux.AcceptStream()
		if err != nil {
			if !errors.Is(err, yamux.ErrSessionShutdown) {
				s.logger.Debug("accept stream ended", "err", err)
			}
			return
		}
		go s.dispatchStream(stream)
	}
}

func (s *Session) dispatchStream(stream *yamux.Stream) {
	_ = stream.SetReadDeadline(time.Now().Add(streamPreambleTimeout))
	var hdr [8]byte
	if _, err := io.ReadFull(stream, hdr[:]); err != nil {
		s.logger.Debug("read preamble failed", "err", err)
		_ = stream.Close()
		return
	}
	_ = stream.SetReadDeadline(time.Time{})

	streamID := binary.BigEndian.Uint64(hdr[:])
	s.mu.Lock()
	pc, ok := s.pending[streamID]
	s.mu.Unlock()
	if !ok {
		s.logger.Warn("stray data stream", "stream_id", streamID)
		_ = stream.Close()
		return
	}
	select {
	case pc.streamCh <- stream:
	default:
		_ = stream.Close()
	}
}
