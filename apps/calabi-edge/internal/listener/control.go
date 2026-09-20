// Package listener houses the goroutines that accept inbound connections
// (client control connections, visitor HTTP/TCP connections).
package listener

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync/atomic"

	"github.com/hashicorp/yamux"

	"github.com/calabinet/calabi/apps/calabi-edge/internal/ratelimit"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/router"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/session"
	proto "github.com/calabinet/calabi/pkg/protocol"
)

// ControlOptions configures the client-facing TLS+yamux listener.
type ControlOptions struct {
	Addr     string
	TLS      *tls.Config
	ServerID string
	Region   string
	// BaseDomain is HTTPListener.BaseDomain from edge config.
	// Surfaced to clients in AUTH_RESP so daemon SPAs can render TCP/UDP
	// public addrs as `<base>:<port>` instead of the misleading
	// `localhost:<port>` they'd get from snap.server_addr in dev. Empty
	// is fine — old daemons fall back to the snap host.
	BaseDomain string
	// HTTPPort / HTTPSPort are the edge's public HTTP / HTTPS listener ports,
	// advertised in AUTH_RESP so a self-hosted console can show a directly-usable
	// URL. 0 = don't advertise (platform edge behind a load balancer).
	HTTPPort  uint32
	HTTPSPort uint32

	Manager *session.Manager
	// Verifier or Grants — exactly one — is how a client is accepted: a token
	// the control plane checks (platform), or a coordinator grant (self-hosted).
	Verifier  session.TokenVerifier
	Grants    session.GrantAuth
	Registrar session.ProxyRegistrar
	Domains   session.DomainAllocator
	Ports     session.PortAllocator
	Persister session.ProxyPersister // optional; tunnel-svc writeback
	Router    *router.Router         // used by ServeHTTP/ServeTCP, kept here only for assertion

	// BandwidthResolver is invoked once per session, post-handshake, to
	// look up the per-customer bandwidth_kbps from quota-svc. nil ⇒
	// "no quota-svc wired"; sessions keep the unlimited default. The
	// resolver MUST degrade open (return zeros on transport failure).
	BandwidthResolver BandwidthResolver

	// OrgBandwidth owns the org-wide tier's shared buckets. nil ⇒ per-tunnel
	// limiting only (which is how a standalone edge runs).
	OrgBandwidth OrgBandwidthRegistry

	// ConnGuardInstaller, when set, runs once per session post-handshake
	// to install the per-org connection guard (concurrent-connection cap
	// + new-connection rate gates, Phase A anti-abuse). It resolves the
	// caps from quota-svc and attaches a *session.ConnGuard. nil ⇒ no
	// connection limiting (dev / standalone). MUST degrade open (leave
	// the session unguarded on any lookup failure) — abuse protection is
	// best-effort and never blocks a paying user on a quota-svc hiccup.
	ConnGuardInstaller ConnGuardInstaller

	// OnlineCapAdmit, when set, is consulted after a successful AUTH but
	// before Manager.Register to refuse the session if the org has
	// reached its max_online_clients cap. nil disables enforcement
	// entirely (the resolver is opt-in: dev / standalone edges without
	// identity-svc + quota-svc wired keep the "everyone in"
	// behaviour). The resolver MUST fail closed — returning allowed=false
	// on any internal error — because admitting on error silently
	// breaks the cap. See apps/calabi-edge/internal/admit for the
	// production implementation.
	OnlineCapAdmit OnlineCapAdmit

	// TrustClientPolicy is the edge's effective standalone decision (computed in
	// main.go as mode==standalone AND no control plane wired): when true the edge
	// applies the per-proxy security policy a client supplies in NEW_PROXY
	// (ProxyOptions.security_config_json). Default false ignores it (platform /
	// BYOI — security is server-authoritative).
	TrustClientPolicy bool

	// Observer receives session + proxy lifecycle callbacks. May be nil.
	Observer ControlObserver

	// PostHandshake runs after AUTH succeeds, in the per-session goroutine,
	// before the control loop reads its first frame. Phase C uses this
	// for the reconnect-catch-up push (fetch all tunnels owned by this
	// client and send them down as CONFIG_PUSH). nil = no hook.
	PostHandshake func(ctx context.Context, sess *session.Session)

	// OnSessionGone fires AFTER the per-session goroutine returns and
	// Manager.Unregister has run — i.e. the session row is gone from
	// the live set. main wires this to kick the presence reporter so
	// identity-svc sees the device as offline within seconds instead
	// of waiting out the 35s freshness window. Should be non-blocking
	// (a buffered-channel send). nil = no hook.
	OnSessionGone func()
}

// BandwidthCaps is the two-tier bandwidth allowance for one session, all in
// bytes/sec:
//
//   - Sustained / Peak apply to EACH TUNNEL of the session
//     (套餐「带宽速度 / 带宽上限」).
//   - OrgSustained / OrgPeak apply to the ORG as a whole — every tunnel of
//     every session that org has on this edge shares them.
//
// 0 means "no limit at this tier"; Peak<=Sustained means no separate burst
// tier. A returned zero value therefore means unlimited everywhere, which is
// what an unresolvable tenant or a quota-svc outage must produce (degrade
// open — an edge that throttles because the control plane blinked is worse
// than one that briefly does not).
type BandwidthCaps struct {
	Sustained    int64
	Peak         int64
	OrgSustained int64
	OrgPeak      int64
}

// BandwidthResolver maps a session's identity tuple to its two-tier cap.
// Empty / non-numeric tenantID yields the zero value — quota-svc keys by
// numeric org_id.
type BandwidthResolver interface {
	BandwidthLimitsBytesPerSec(ctx context.Context, tenantID, workspaceID string) BandwidthCaps
}

// OrgBandwidthRegistry hands out the org-wide bucket shared by every session
// of one org on this edge, reference-counted by session.
// *ratelimit.OrgRegistry implements it; the seam exists so control.go does
// not have to reach for the concrete type (and tests can count acquires).
type OrgBandwidthRegistry interface {
	Acquire(orgID, sustainedBps, peakBps int64) *ratelimit.Limiter
	Release(orgID int64)
}

// ConnGuardInstaller resolves a session's per-org connection caps from
// quota-svc and installs a *session.ConnGuard on it (Phase A anti-abuse).
// tenantID is the numeric org_id in string form; non-numeric tenants
// (static-YAML dev) are left unguarded. The implementation lives in
// calabi-edge's main (it owns the process-global limiters + quota client);
// control.go only knows this seam so it can fire it at the right point in
// the handshake (right after the bandwidth cap, before Register).
type ConnGuardInstaller interface {
	InstallConnGuard(ctx context.Context, sess *session.Session, tenantID string)
}

// OnlineCapAdmit decides whether a freshly-authenticated session may
// register, based on the org's max_online_clients quota. Reason is a
// human-readable string surfaced in the ERROR frame the client sees.
//
// Limit is the configured cap (-1 = unlimited; the resolver SHOULD
// return Allowed=true in that case). Limit + Current are also passed
// through into AUTH_RESP.Quotas so the client UI can render an
// accurate "n/N" hint without an extra round-trip to bff-console.
type OnlineCapAdmit interface {
	AdmitNewSession(ctx context.Context, orgID string) AdmitDecision
}

// AdmitDecision is the OnlineCapAdmit return value.
type AdmitDecision struct {
	Allowed bool
	Current int32
	Limit   int32 // -1 = unlimited (UI hides the counter then)
	Reason  string
}

// ControlObserver is the metrics surface for the control listener. session
// callbacks are routed through *session.Manager; this interface covers the
// handshake-only signals that aren't seen by the Manager.
type ControlObserver interface {
	OnHandshakeFailure(reason string)
}

// Control listens for incoming client connections, performs TLS + yamux +
// HELLO/AUTH handshakes, then spawns the per-session control loop.
type Control struct {
	opts   ControlOptions
	logger *slog.Logger

	ln       net.Listener
	stopping atomic.Bool
}

// NewControl builds an unstarted Control listener.
func NewControl(logger *slog.Logger, opts ControlOptions) *Control {
	return &Control{
		opts:   opts,
		logger: logger.With("component", "listener.control"),
	}
}

// Run blocks accepting connections until ctx is cancelled or Listen fails.
func (c *Control) Run(ctx context.Context) error {
	if c.opts.TLS == nil {
		return errors.New("listener.control: TLS config required")
	}
	if c.opts.Manager == nil || c.opts.Registrar == nil {
		return errors.New("listener.control: manager/registrar required")
	}
	if (c.opts.Verifier == nil) == (c.opts.Grants == nil) {
		return errors.New("listener.control: exactly one of a token verifier and grant auth required")
	}
	ln, err := tls.Listen("tcp", c.opts.Addr, c.opts.TLS)
	if err != nil {
		return fmt.Errorf("tls listen %s: %w", c.opts.Addr, err)
	}
	c.ln = ln
	c.logger.Info("control listener up", "addr", c.opts.Addr)

	go func() {
		<-ctx.Done()
		c.stopping.Store(true)
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if c.stopping.Load() {
				return nil
			}
			c.logger.Warn("accept failed", "err", err)
			continue
		}
		go c.handle(ctx, conn)
	}
}

func (c *Control) handle(ctx context.Context, conn net.Conn) {
	remote := conn.RemoteAddr().String()
	c.logger.Debug("incoming control conn", "remote", remote)

	// yamux server side: client opens the control stream first.
	mux, err := yamux.Server(conn, nil)
	if err != nil {
		c.logger.Warn("yamux server failed", "err", err)
		c.recordHandshakeFailure("yamux")
		_ = conn.Close()
		return
	}
	ctrl, err := mux.AcceptStream()
	if err != nil {
		_ = mux.Close()
		if errors.Is(err, io.EOF) {
			// Connected, maybe completed TLS, and left without a word: a
			// self-hosted coordinator reading this edge's certificate (once a
			// minute), or a TCP health check. Not a client that failed.
			c.logger.Debug("connection closed before a control stream", "remote", remote)
			return
		}
		c.logger.Warn("accept control stream failed", "err", err)
		c.recordHandshakeFailure("accept_stream")
		return
	}

	sess := session.New(c.logger.With("remote", remote), mux, ctrl)
	sess.ID = c.opts.Manager.NewSessionID()
	sess.TrustClientPolicy = c.opts.TrustClientPolicy

	res, err := sess.PerformServerHandshake(c.opts.ServerID, c.opts.Region, c.opts.BaseDomain, c.opts.HTTPPort, c.opts.HTTPSPort, c.opts.Verifier, c.opts.Grants)
	if err != nil {
		c.logger.Info("handshake failed", "err", err, "remote", remote)
		c.recordHandshakeFailure("auth")
		_ = sess.Close()
		return
	}
	c.logger.Info("session established",
		"session_id", sess.ID,
		"tenant_id", res.TenantID,
		"client_id", res.ClientID,
		"remote", remote,
	)

	// max_online_clients gate. Runs after AUTH_RESP so the client
	// already knows its session id (handy for log correlation), but
	// before Manager.Register so an over-cap client never appears in
	// the Manager's active set. On deny we send an ERROR frame with
	// the quota_exceeded code so the client UI can surface a useful
	// message, then close — the client treats this like any other
	// post-handshake server-initiated tear-down.
	if c.opts.OnlineCapAdmit != nil {
		decision := c.opts.OnlineCapAdmit.AdmitNewSession(ctx, res.TenantID)
		if !decision.Allowed {
			c.logger.Info("session denied by online-cap",
				"session_id", sess.ID, "tenant_id", res.TenantID,
				"current", decision.Current, "limit", decision.Limit,
				"reason", decision.Reason)
			c.recordHandshakeFailure("online_cap")
			reason := decision.Reason
			if reason == "" {
				reason = fmt.Sprintf("max online clients reached (%d/%d)",
					decision.Current, decision.Limit)
			}
			_ = sess.SendControl(proto.FrameError, proto.NewError(
				proto.CodeQuotaExceeded,
				"calabi.err.quota.online_clients",
				reason,
			))
			_ = sess.Close()
			return
		}
	}

	// Bandwidth lookup. Resolve
	// before we accept proxies so the very first NEW_CONN already sees the
	// correct caps — the per-tunnel rates must be on the session before any
	// RegisterProxy builds a tunnel's bucket from them.
	if release := c.installBandwidth(ctx, sess, res.TenantID, res.WorkspaceID); release != nil {
		defer release()
	}

	// Connection guard (Phase A anti-abuse): install the per-org
	// concurrent-connection cap + new-connection rate gates. Degrades open
	// (installer leaves the session unguarded) on any quota lookup failure.
	if c.opts.ConnGuardInstaller != nil {
		c.opts.ConnGuardInstaller.InstallConnGuard(ctx, sess, res.TenantID)
	}

	c.opts.Manager.Register(sess)
	// Defer chain runs LIFO: OnSessionGone fires AFTER Unregister so the
	// presence kick observes the session already removed from the live
	// set. Without that ordering the immediate publish would still
	// include this dying session and the delete-absent path on identity-
	// svc wouldn't fire until the next regular tick — exactly the lag
	// is fixing.
	defer func() {
		if c.opts.OnSessionGone != nil {
			c.opts.OnSessionGone()
		}
	}()
	defer c.opts.Manager.Unregister(sess.ID)

	if c.opts.PostHandshake != nil {
		c.opts.PostHandshake(ctx, sess)
	}

	sess.StartStreamAcceptor()
	sess.Loop(ctx, c.opts.Registrar, c.opts.Domains, c.opts.Ports, c.opts.Manager.Observer(), c.opts.Persister)
}

// installBandwidth puts both bandwidth tiers on a freshly-authenticated
// session and returns the org tier's release, or nil when there is nothing to
// release. The caller defers it; nothing else may call it.
//
// It is a method rather than inline code in serveConn for one reason: serveConn
// needs a full TLS + yamux + AUTH handshake to reach, so inline code here could
// only be tested through a client implementation nobody has written. Splitting
// it lets the test drive the exact code the handshake runs — which matters most
// for the release path, whose failure mode (a leaked refcount keeping an org's
// bucket alive forever) is invisible until an edge has been up for weeks.
func (c *Control) installBandwidth(ctx context.Context, sess *session.Session, tenantID, workspaceID string) func() {
	if c.opts.BandwidthResolver == nil {
		return nil
	}
	caps := c.opts.BandwidthResolver.BandwidthLimitsBytesPerSec(ctx, tenantID, workspaceID)
	sess.SetBandwidthLimit(caps.Sustained, caps.Peak)

	// Org tier: one bucket per org, shared with that org's other sessions on
	// this edge and freed when the last of them ends. Keyed on the session's
	// resolved org id — 0 (unresolvable / dev tenant) means no org tier.
	var release func()
	if c.opts.OrgBandwidth != nil && caps.OrgSustained > 0 {
		if orgID := sess.OrgID(); orgID > 0 {
			sess.SetOrgLimiter(c.opts.OrgBandwidth.Acquire(orgID, caps.OrgSustained, caps.OrgPeak))
			release = func() { c.opts.OrgBandwidth.Release(orgID) }
		}
	}
	if caps.Sustained > 0 || caps.OrgSustained > 0 {
		c.logger.Info("session bandwidth caps installed",
			"session_id", sess.ID,
			"tunnel_sustained_bytes_per_sec", caps.Sustained,
			"tunnel_peak_bytes_per_sec", caps.Peak,
			"org_sustained_bytes_per_sec", caps.OrgSustained,
			"org_peak_bytes_per_sec", caps.OrgPeak,
			"org_tier_active", sess.OrgLimiter() != nil)
	}
	return release
}

func (c *Control) recordHandshakeFailure(reason string) {
	if c.opts.Observer != nil {
		c.opts.Observer.OnHandshakeFailure(reason)
	}
}
