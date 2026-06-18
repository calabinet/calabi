// Package session owns the client-side session lifecycle: handshake,
// heartbeat, NEW_PROXY registration, and dispatch of inbound NEW_CONN to
// local-dial workers.
package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/calabi/calabi/apps/client/internal/transport"
	proto "github.com/calabi/calabi/pkg/protocol"
)

// Tunnel describes one tunnel the user wants the client to register.
type Tunnel struct {
	Name      string
	Type      proto.ProxyKind
	LocalAddr string // e.g. "127.0.0.1:8080"
	Domain    string // optional, HTTP (full host; takes precedence over Subdomain)
	// Subdomain is a requested platform subdomain PREFIX (one DNS label, e.g.
	// "myapp") for http/https. The standalone supervisor resolves it to
	// <Subdomain>.<edge base_domain> at register time (mirrors the platform
	// edge's resolveProxyHost). Ignored when Domain is set. The proto NEW_PROXY
	// carries only the resolved full Domain — there is no subdomain on the wire.
	Subdomain  string
	RemotePort uint32 // optional, TCP
	// SecurityConfigJSON, when non-empty, is a `{"security":{…}}` config_json
	// blob sent to the edge in NEW_PROXY (ProxyOptions.security_config_json).
	// It only takes effect against a STANDALONE / self-hosted edge (the edge
	// must run with standalone=true); a managed edge ignores it. Built by the
	// CLI from --ip-allow/--basic-auth/--rate/--set-header/--oauth-* flags.
	SecurityConfigJSON string
}

// StatusTracker is the small interface the client session uses to push
// runtime state into the local /status page. A nil tracker is a no-op.
//
// UpsertPending / RemovePending power Phase C's server→client tunnel
// sync: when the edge pushes a CONFIG_PUSH announcing a console-
// created tunnel for this device, we surface it on the status page
// so the user can see it's queued even before they activate the
// matching local upstream.
type StatusTracker interface {
	SetConnected(connected bool, sessionID, tenantID, clientID, baseDomain, serverIP string, httpPort, httpsPort uint32)
	AddBytes(proxyID, direction string, n int64)
	AddConnection(proxyID string)
	UpsertPending(tunnelID int64, name, kind, localAddr, domain string, remotePort uint32)
	RemovePendingByTunnelID(tunnelID int64)
	// AddActiveTunnel registers a fully-claimed tunnel into the status
	// tracker so subsequent AddBytes/AddConnection calls have a key to
	// land on. The single-tunnel CLIs (calabi http/tcp/udp/sni) call
	// State.AddTunnel directly; daemon-mode auto-claim goes through
	// this interface method so session/ doesn't import status.
	AddActiveTunnel(proxyID string, tunnelID int64, name, kind, localAddr, publicAddr string)
	// RemoveActiveTunnel forgets a tunnel after a server-side close
	// (CONFIG_PUSH with close_proxy_ids).
	RemoveActiveTunnel(proxyID string)
	// ReconcileToTunnelIDs drops every active+pending row whose
	// tunnel_id is not in keep, returning the proxy_ids of dropped
	// ACTIVE rows so the caller can also unwind the proxy registry +
	// send CLOSE_PROXY. Used on FullSync catch-up pushes.
	ReconcileToTunnelIDs(keep map[int64]struct{}) []string
}

// ConnectionInspector is the optional pluggable inspector the
// daemon installs. Per-conn Begin returns an opaque handle that End
// receives back — this keeps session/ from importing internal/inspect
// (which would cycle inspect → session via the tap helpers).
//
// The capture write-buffers (req/resp) are also opaque: implementations
// can return nil to disable HTTP-body capture for that connection,
// e.g. on TCP/UDP tunnels where there's no HTTP to parse.
type ConnectionInspector interface {
	// Begin opens a new connection record. The handle is whatever the
	// implementation wants (typically *inspect.Connection).
	// reqBuf/respBuf, if non-nil, are TeeReader-targets the session
	// writes the visitor↔local bytes into for later HTTP parsing.
	Begin(proxyID, visitorIP, kind string) (handle any, reqBuf io.Writer, respBuf io.Writer)
	// End records the close + triggers any post-conn parsing.
	End(handle any, bytesIn, bytesOut int64, err error)
}

// Client is one connected session against an edge node.
type Client struct {
	logger   *slog.Logger
	mux      *transport.Mux
	ctrl     *frameStream
	token    string
	clientNm string
	deviceID int64 // identity-svc clients.id; 0 = unknown

	mu                sync.Mutex
	heartbeatInterval time.Duration
	tenantID          string
	clientID          string
	sessionID         string

	tracker   StatusTracker
	inspector ConnectionInspector

	// autoClaim, when true, makes handleConfigPush automatically send a
	// NEW_PROXY (with claim_tunnel_id set) for each UpsertProxy entry
	// instead of just listing it as pending on the /status page. Set by
	// `calabi daemon`; off by default so the single-tunnel CLI modes
	// (`calabi http <port>` etc.) don't double-register their own tunnel.
	autoClaim bool

	// proxyResolver, when set, lets handleConfigPush extend the live
	// proxy registry — daemon-mode auto-claim installs the proxy_id →
	// tunnel mapping so subsequent NEW_CONN frames find the local upstream.
	// Set by AttachProxyResolver. Read-locked on every NEW_CONN.
	proxyResolver ProxyRegistry

	// claiming closes a TOCTOU race in autoClaimOne. The edge can re-push the
	// same tunnel's CONFIG_PUSH more than once on a reconnect (full-sync
	// catch-up + delta), and each upsert runs autoClaimOne in its own
	// goroutine. The registry idempotency check (ProxyIDByTunnelID) and the
	// NEW_PROXY register are not atomic, so two concurrent goroutines could
	// both pass the check and both claim — the second then hits the edge's
	// "code=3001 domain already registered" and leaves a pending ghost row.
	// This set marks a tunnel_id as claim-in-flight so a concurrent duplicate
	// skips instead. Guarded by mu.
	claiming map[int64]bool

	// lastUpsertLog remembers the last-logged content fingerprint per
	// tunnel_id so a repeated CONFIG_PUSH for an UNCHANGED tunnel logs at
	// Debug instead of spamming an identical INFO line. The edge re-pushes the
	// same tunnel on FullSync + delta overlap, so without this the dashboard
	// fills with duplicate "config push upsert" rows. New/changed content
	// still logs at INFO. Guarded by mu; lives for the session (a reconnect
	// builds a fresh Client, so each session's FullSync logs once).
	lastUpsertLog map[int64]string

	// pendingNewProxy delivers the next NEW_PROXY_RESP frame to whichever
	// goroutine is awaiting it. nil when no live RegisterTunnelLive call
	// is in flight (Run() then logs the orphan frame and drops it).
	//
	// One channel slot is enough because newProxyMu serializes concurrent
	// RegisterTunnelLive callers — only one outstanding NEW_PROXY at a
	// time per session, matching how the edge handles them serially in
	// its control loop anyway.
	newProxyMu      sync.Mutex
	pendingNewProxy chan *proto.NewProxyResponse
}

// ProxyRegistry is the small dynamic registry the daemon command uses to
// add / remove proxies as CONFIG_PUSH arrives. The session itself doesn't
// own the registry (the CLI does, so the /status page can introspect it),
// but it needs an Upsert / Remove pair for the auto-claim path to work.
type ProxyRegistry interface {
	UpsertProxy(proxyID string, t Tunnel)
	RemoveProxy(proxyID string)
	ProxyIDByTunnelID(tunnelID int64) (string, bool)
}

// TunnelIDIndexer is an optional add-on a ProxyRegistry implementation may
// satisfy to receive the tunnel_id → proxy_id mapping on each auto-claim.
// The session's Tunnel struct doesn't carry the tunnel_id natively, so we
// hand it off via this side channel — the daemon uses it to power the
// CONFIG_PUSH delete path's lookup by tunnel_id.
type TunnelIDIndexer interface {
	NoteTunnelID(tunnelID int64, proxyID string)
}

// RegisteredTunnelLookup is an optional ProxyRegistry add-on that lets
// autoClaimOne read back the Tunnel currently registered for a tunnel_id. It
// uses this to tell a genuine idempotent catch-up (same upstream → skip) apart
// from a console EDIT of local_addr (changed upstream → close + re-register so
// new connections dial the new target). Registries that don't implement it keep
// the plain idempotent-skip behavior.
type RegisteredTunnelLookup interface {
	RegisteredTunnel(tunnelID int64) (Tunnel, bool)
}

// New wires a Client over an established Mux.
func New(logger *slog.Logger, mux *transport.Mux, token, clientName string) *Client {
	return &Client{
		logger:            logger.With("component", "client.session"),
		mux:               mux,
		ctrl:              newFrameStream(mux.Control),
		token:             token,
		clientNm:          clientName,
		heartbeatInterval: 15 * time.Second,
	}
}

// SetDeviceID attaches the identity-svc clients.id this session should
// announce in its AUTH frame for live-presence tracking. Call before
// Handshake; 0 = unknown (Phase A's fallback for un-registered clients).
func (c *Client) SetDeviceID(id int64) {
	c.mu.Lock()
	c.deviceID = id
	c.mu.Unlock()
}

// AttachTracker hooks a StatusTracker for /status page updates. Safe to
// call before or after Handshake; callbacks made before attach are simply
// missed (the page just shows pre-attach state).
func (c *Client) AttachTracker(t StatusTracker) {
	c.mu.Lock()
	c.tracker = t
	c.mu.Unlock()
}

// AttachInspector hooks a ConnectionInspector. daemon wires this
// to inspect.ConnectionLog + inspect.HTTPLog so the UI can show
// per-connection details and replay HTTP requests.
func (c *Client) AttachInspector(i ConnectionInspector) {
	c.mu.Lock()
	c.inspector = i
	c.mu.Unlock()
}

// EnableAutoClaim makes handleConfigPush actively claim each UpsertProxy
// by sending NEW_PROXY (with claim_tunnel_id), then upserting the result
// into the registry. Call before Handshake from `calabi daemon`; leaves
// the single-tunnel CLI modes untouched.
//
// Requires AttachProxyResolver to also be called with a live registry,
// otherwise auto-claim has nowhere to write the proxy_id mapping.
func (c *Client) EnableAutoClaim() {
	c.mu.Lock()
	c.autoClaim = true
	c.mu.Unlock()
}

// AttachProxyResolver hooks a dynamic ProxyRegistry — the daemon-mode
// counterpart to the static resolver func that the single-tunnel CLIs
// pass into Run(). When set, handleConfigPush writes through to it on
// auto-claim success / close, and Run()'s NEW_CONN dispatcher consults
// it as a fallback when the static resolver returns false.
func (c *Client) AttachProxyResolver(r ProxyRegistry) {
	c.mu.Lock()
	c.proxyResolver = r
	c.mu.Unlock()
}

// Handshake completes HELLO + AUTH against the edge node.
func (c *Client) Handshake(ctx context.Context) error {
	hello := &proto.HelloRequest{
		ProtocolMajor: uint32(proto.CurrentMajor),
		ClientVersion: "calabi/0.1.0-m3-sprint2",
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		Ts:            time.Now().UnixMilli(),
		Features:      []string{"http", "tcp", "udp", "sni"},
	}
	if err := c.ctrl.WritePayload(proto.FrameHello, hello); err != nil {
		return fmt.Errorf("send HELLO: %w", err)
	}

	f, err := c.ctrl.Read()
	if err != nil {
		return fmt.Errorf("read HELLO_ACK: %w", err)
	}
	if f.Type != proto.FrameHelloAck {
		return fmt.Errorf("want HELLO_ACK, got %s", f.Type)
	}
	var ack proto.HelloAck
	if err := proto.Unmarshal(f.Payload, &ack); err != nil {
		return fmt.Errorf("unmarshal HELLO_ACK: %w", err)
	}
	if ack.HeartbeatIntervalMs > 0 {
		c.heartbeatInterval = time.Duration(ack.HeartbeatIntervalMs) * time.Millisecond
	}
	c.logger.Info("server hello",
		"server_id", ack.ServerID, "region", ack.Region,
		"heartbeat_ms", ack.HeartbeatIntervalMs)

	c.mu.Lock()
	devID := c.deviceID
	c.mu.Unlock()
	auth := &proto.AuthRequest{
		Token:      c.token,
		ClientName: c.clientNm,
		DeviceID:   devID,
	}
	if err := c.ctrl.WritePayload(proto.FrameAuth, auth); err != nil {
		return fmt.Errorf("send AUTH: %w", err)
	}
	f, err = c.ctrl.Read()
	if err != nil {
		return fmt.Errorf("read AUTH_RESP: %w", err)
	}
	if f.Type != proto.FrameAuthResp {
		return fmt.Errorf("want AUTH_RESP, got %s", f.Type)
	}
	var ar proto.AuthResponse
	if err := proto.Unmarshal(f.Payload, &ar); err != nil {
		return err
	}
	if ar.Error != nil {
		return ar.Error
	}
	c.mu.Lock()
	c.tenantID = ar.TenantID
	c.clientID = ar.ClientID
	c.sessionID = ar.SessionID
	tracker := c.tracker
	c.mu.Unlock()
	// also stamp the resolved edge IP from the mux's underlying
	// TCP/TLS connection. snap.server_addr holds whatever the daemon
	// dialed (could be a hostname like "localhost" or "edge.calabi.net");
	// snap.server_ip holds the resolved dotted-decimal IP that the SPA
	// can render as the TCP/UDP public addr ("127.0.0.1:20000",
	// "1.2.3.4:20000"). Empty if Conn doesn't expose it (shouldn't happen
	// with real TCP conns, but the SPA falls back gracefully).
	serverIP := c.mux.RemoteIP()
	if tracker != nil {
		tracker.SetConnected(true, ar.SessionID, ar.TenantID, ar.ClientID, ar.BaseDomain, serverIP, ar.HTTPPort, ar.HTTPSPort)
	}
	c.logger.Info("authenticated",
		"tenant_id", ar.TenantID, "client_id", ar.ClientID, "session_id", ar.SessionID,
		"base_domain", ar.BaseDomain, "server_ip", serverIP,
		"http_port", ar.HTTPPort, "https_port", ar.HTTPSPort)
	return nil
}

// RegisterTunnel sends NEW_PROXY and returns the server-assigned address.
type Assigned struct {
	ProxyID    string
	Domain     string
	RemotePort uint32
}

func (c *Client) RegisterTunnel(ctx context.Context, t Tunnel) (Assigned, error) {
	req := &proto.NewProxyRequest{
		Name:       t.Name,
		Type:       t.Type,
		LocalAddr:  t.LocalAddr,
		Domain:     t.Domain,
		RemotePort: t.RemotePort,
	}
	if t.SecurityConfigJSON != "" {
		req.Options = &proto.ProxyOptions{SecurityConfigJSON: t.SecurityConfigJSON}
	}
	if err := c.ctrl.WritePayload(proto.FrameNewProxy, req); err != nil {
		return Assigned{}, fmt.Errorf("send NEW_PROXY: %w", err)
	}
	// The edge may interleave CONFIG_PUSH (tunnel-config sync) or PING
	// (heartbeat) frames before our NEW_PROXY_RESP — e.g. when a daemon for
	// the same client is already online, the edge pushes the org's config on
	// every new session. A foreground `calabi http` doesn't act on those
	// (cli.Run handles them once serving starts), so skip them here and keep
	// reading until the response we asked for, rather than aborting with
	// "want NEW_PROXY_RESP, got CONFIG_PUSH".
	for {
		f, err := c.ctrl.Read()
		if err != nil {
			return Assigned{}, fmt.Errorf("read NEW_PROXY_RESP: %w", err)
		}
		switch f.Type {
		case proto.FrameNewProxyResp:
			var resp proto.NewProxyResponse
			if err := proto.Unmarshal(f.Payload, &resp); err != nil {
				return Assigned{}, err
			}
			if resp.Error != nil {
				return Assigned{}, resp.Error
			}
			return Assigned{
				ProxyID:    resp.ProxyID,
				Domain:     resp.Domain,
				RemotePort: resp.RemotePort,
			}, nil
		case proto.FrameConfigPush, proto.FramePing, proto.FramePong:
			// Benign interleaved control frames — ignore and keep waiting.
			continue
		default:
			return Assigned{}, fmt.Errorf("want NEW_PROXY_RESP, got %s", f.Type)
		}
	}
}

// RegisterTunnelLive is the Run()-loop-safe counterpart of RegisterTunnel.
//
// Use this from goroutines spawned after Run() has started reading the
// control stream — calling the synchronous RegisterTunnel from there
// would race with Run's own ctrl.Read(). RegisterTunnelLive instead
// writes NEW_PROXY and waits for Run() to hand the matching
// NEW_PROXY_RESP back via the pendingNewProxy channel.
//
// claimTunnelID, when non-zero, asks the edge to claim an existing
// tunnel-svc row (see proto.NewProxyRequest.ClaimTunnelID) instead of
// inserting a new one. The daemon-mode auto-claim path uses this.
//
// Concurrency: only one in-flight RegisterTunnelLive call per Client at
// a time (serialized by newProxyMu). The protocol doesn't carry a
// correlation id, so we'd lose the ability to match responses to senders
// if we let multiple NEW_PROXY frames overlap.
func (c *Client) RegisterTunnelLive(ctx context.Context, t Tunnel, claimTunnelID int64) (Assigned, error) {
	c.newProxyMu.Lock()
	defer c.newProxyMu.Unlock()

	ch := make(chan *proto.NewProxyResponse, 1)
	c.mu.Lock()
	c.pendingNewProxy = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.pendingNewProxy = nil
		c.mu.Unlock()
	}()

	req := &proto.NewProxyRequest{
		Name:          t.Name,
		Type:          t.Type,
		LocalAddr:     t.LocalAddr,
		Domain:        t.Domain,
		RemotePort:    t.RemotePort,
		ClaimTunnelID: claimTunnelID,
	}
	if t.SecurityConfigJSON != "" {
		req.Options = &proto.ProxyOptions{SecurityConfigJSON: t.SecurityConfigJSON}
	}
	if err := c.ctrl.WritePayload(proto.FrameNewProxy, req); err != nil {
		return Assigned{}, fmt.Errorf("send NEW_PROXY: %w", err)
	}
	select {
	case <-ctx.Done():
		return Assigned{}, ctx.Err()
	case resp := <-ch:
		if resp == nil {
			return Assigned{}, fmt.Errorf("session closed before NEW_PROXY_RESP")
		}
		if resp.Error != nil {
			return Assigned{}, resp.Error
		}
		return Assigned{
			ProxyID:    resp.ProxyID,
			Domain:     resp.Domain,
			RemotePort: resp.RemotePort,
		}, nil
	}
}

// CloseTunnel sends CLOSE_PROXY for the given proxy_id. Fire-and-forget;
// the edge response (if any) is logged but not awaited. Used by the
// daemon-mode CONFIG_PUSH delete handler.
func (c *Client) CloseTunnel(proxyID, reason string) error {
	if proxyID == "" {
		return nil
	}
	return c.ctrl.WritePayload(proto.FrameCloseProxy, &proto.CloseProxyRequest{
		ProxyID: proxyID,
		Reason:  reason,
	})
}

// Run starts the heartbeat + dispatch loops and blocks until ctx is done
// or the control stream closes.
//
// proxiesByID tells the dispatcher how to resolve a NEW_CONN.proxy_id to
// a local address. It is owned by the caller (CLI) so dynamic add/remove
// is possible later.
func (c *Client) Run(ctx context.Context, proxiesByID func(string) (Tunnel, bool)) error {
	defer func() {
		c.mu.Lock()
		tracker := c.tracker
		sessID := c.sessionID
		tenant := c.tenantID
		clientID := c.clientID
		c.mu.Unlock()
		if tracker != nil {
			// SetConnected(false) clears baseDomain + serverIP — once the
			// session is down, those values are stale. Next AUTH_RESP
			// refreshes them.
			tracker.SetConnected(false, sessID, tenant, clientID, "", "", 0, 0)
		}
		c.mux.Close()
	}()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Unblock the blocking c.ctrl.Read() below when ctx is cancelled.
	//
	// The control loop checks ctx.Done() only at the TOP of each iteration,
	// then parks in c.ctrl.Read() waiting for the next frame. The control
	// stream is idle most of the time (a steady tunnel sends no control
	// frames), so the loop is almost always blocked inside that Read —
	// cancelling ctx (Ctrl+C / SIGTERM, or a daemon session-kill) does
	// nothing on its own, because yamux Read doesn't honour a context.
	// The process then appears to ignore Ctrl+C until the edge happens to
	// send a frame or the TCP connection dies (up to the keep-alive
	// timeout, i.e. minutes) — the "无法用 Ctrl+C 终止" symptom.
	//
	// Closing the mux makes the parked yamux Read return an error, the loop
	// unwinds, and the deferred mux.Close() (idempotent) finishes cleanup.
	// defer cancel() above guarantees this goroutine always wakes and exits,
	// including on a normal EOF return, so it never leaks.
	go func() {
		<-ctx.Done()
		c.mux.Close()
	}()

	// Heartbeat.
	go c.heartbeat(ctx)

	// Control loop.
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		f, err := c.ctrl.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("control read: %w", err)
		}
		switch f.Type {
		case proto.FrameNewConn:
			var req proto.NewConnRequest
			if err := proto.Unmarshal(f.Payload, &req); err != nil {
				c.logger.Warn("bad NEW_CONN", "err", err)
				continue
			}
			go c.handleNewConn(ctx, &req, proxiesByID)

		case proto.FrameNewProxyResp:
			// Route to whichever goroutine called RegisterTunnelLive. Drop
			// silently if nobody is waiting — that means a pre-Run sync
			// RegisterTunnel raced or the edge sent a duplicate; neither
			// is fatal.
			var resp proto.NewProxyResponse
			if err := proto.Unmarshal(f.Payload, &resp); err != nil {
				c.logger.Warn("bad NEW_PROXY_RESP", "err", err)
				continue
			}
			c.mu.Lock()
			ch := c.pendingNewProxy
			c.mu.Unlock()
			if ch != nil {
				select {
				case ch <- &resp:
				default:
					c.logger.Warn("NEW_PROXY_RESP slot full, dropping",
						"proxy_id", resp.ProxyID)
				}
			} else {
				c.logger.Debug("orphan NEW_PROXY_RESP", "proxy_id", resp.ProxyID)
			}

		case proto.FrameConfigPush:
			c.handleConfigPush(ctx, f.Payload)

		case proto.FramePong:
			// no-op

		case proto.FrameGoAway:
			c.logger.Info("server requested go-away; reconnect later")
			cancel()
			return nil

		case proto.FrameError:
			var e proto.ErrorPayload
			_ = proto.Unmarshal(f.Payload, &e)
			c.logger.Warn("server error", "code", e.Code, "msg", e.MessageEN)
			// Server-initiated terminal errors: tear the loop down so
			// the daemon reconnect loop can inspect the reason. Without
			// this, we'd just log + continue, eventually return nil on
			// EOF when the edge closes the stream, and the daemon would
			// silently reconnect into the same refusal forever. The
			// terminal set is the over-cap codes (quota_exceeded /
			// online client cap) and any future "stop trying" code we
			// add — for non-terminal codes we keep logging + carrying
			// on, which preserves the pre-2026-05-28 behaviour.
			if isTerminalServerError(e.Code) {
				cancel()
				return &e
			}

		default:
			c.logger.Debug("unhandled frame", "type", f.Type.String())
		}
	}
}

// isTerminalServerError lists the proto error codes that should tear
// down the client session loop instead of letting it limp along on
// the stale stream. The daemon's outer reconnect loop reads
// proto.ErrorPayload.Code via errors.As to decide whether to mark
// LifecycleFatal — quota over-cap shouldn't trigger an immediate
// reconnect-storm, but a transient FrameError mid-stream should.
func isTerminalServerError(code int) bool {
	switch code {
	case proto.CodeQuotaExceeded,
		proto.CodeQuotaTunnels,
		proto.CodeAuthInvalidToken,
		proto.CodeTenantSuspended,
		proto.CodeForbidden:
		return true
	}
	return false
}

func (c *Client) heartbeat(ctx context.Context) {
	tk := time.NewTicker(c.heartbeatInterval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			err := c.ctrl.WritePayload(proto.FramePing, &proto.Ping{
				ClientSendNs: time.Now().UnixNano(),
			})
			if err != nil {
				c.logger.Warn("heartbeat write failed", "err", err)
				return
			}
		}
	}
}

// handleConfigPush projects a CONFIG_PUSH frame onto the local state:
//
//   - status tracker /status page (always, even in non-daemon mode)
//   - daemon-mode auto-claim: for each upsert, spawn a goroutine that
//     calls RegisterTunnelLive with claim_tunnel_id, then upserts the
//     proxy_id → tunnel mapping into the dynamic registry so NEW_CONN
//     can find the local upstream. On error the entry stays as "pending"
//     in the status page — caller is expected to look at the logs.
//   - daemon-mode close: for each close_proxy_id (the edge sends the
//     tunnel_id as a string), look up the proxy_id in the registry and
//     send CLOSE_PROXY so the edge's local router teardown completes
//     even when the client initiated nothing.
//
// ctx is the Run-loop context; spawned auto-claim goroutines inherit it
// so they unwind on session shutdown.
func (c *Client) handleConfigPush(ctx context.Context, payload []byte) {
	var push proto.ConfigPush
	if err := proto.Unmarshal(payload, &push); err != nil {
		c.logger.Warn("bad CONFIG_PUSH", "err", err)
		return
	}
	c.mu.Lock()
	tracker := c.tracker
	autoClaim := c.autoClaim
	registry := c.proxyResolver
	c.mu.Unlock()

	// FullSync pushes: the edge is telling us "this is the complete
	// authoritative tunnel list for you" (typically the post-handshake
	// catch-up). We do two passes:
	//
	//   (a) Prune the status tracker so anything we used to think was
	//       live but the server doesn't acknowledge gets dropped.
	//   (b) Clear registry entries for tunnel_ids we ARE about to
	//       re-claim, so autoClaimOne's idempotent-skip doesn't think
	//       they're already live on the wire.
	//
	// (b) is the fix for the post-edge-restart bug: the edge resets its
	// router to empty on boot, but the client's registry still holds
	// the previous session's proxy_id → tunnel mapping. Without this
	// clear, autoClaimOne would skip NEW_PROXY for every tunnel in the
	// catch-up, leaving the edge router empty and every visitor request
	// getting 502 "no tunnel for host" until the user restarts the
	// client.
	if push.FullSync {
		keep := make(map[int64]struct{}, len(push.UpsertProxies))
		for _, up := range push.UpsertProxies {
			if up.TunnelID > 0 {
				keep[up.TunnelID] = struct{}{}
			}
		}
		var dropped []string
		if tracker != nil {
			dropped = tracker.ReconcileToTunnelIDs(keep)
		}
		if registry != nil {
			// (a) registry-side teardown for stale rows
			for _, proxyID := range dropped {
				registry.RemoveProxy(proxyID)
			}
			// (b) clear in-keep entries so autoClaimOne re-sends
			// NEW_PROXY. The stale proxy_id → tunnel mapping is
			// session-scoped; the new edge session has none of these.
			reclaim := 0
			for _, up := range push.UpsertProxies {
				if up.TunnelID <= 0 {
					continue
				}
				if proxyID, ok := registry.ProxyIDByTunnelID(up.TunnelID); ok {
					registry.RemoveProxy(proxyID)
					if tracker != nil {
						// AddActiveTunnel below will repopulate, but
						// dropping the old row keeps the SPA "活跃
						// 隧道" count honest in the brief window.
						tracker.RemoveActiveTunnel(proxyID)
					}
					reclaim++
				}
			}
			if reclaim > 0 || len(dropped) > 0 {
				c.logger.Info("full-sync registry reset",
					"dropped_stale", len(dropped),
					"clear_for_reclaim", reclaim,
					"keep", len(keep))
			}
		}
	}

	for _, up := range push.UpsertProxies {
		up := up // capture for goroutine
		if tracker != nil {
			tracker.UpsertPending(up.TunnelID, up.Name, string(up.Type), up.LocalAddr, up.Domain, up.RemotePort)
		}
		// Repeated upsert for an unchanged tunnel → Debug, not INFO. The edge
		// re-pushes the same tunnel (FullSync + delta overlap); an identical
		// INFO line per push is pure noise. New/changed content still INFOs.
		fp := fmt.Sprintf("%s|%s|%s|%s|%d",
			up.Name, string(up.Type), up.LocalAddr, up.Domain, up.RemotePort)
		c.mu.Lock()
		if c.lastUpsertLog == nil {
			c.lastUpsertLog = make(map[int64]string)
		}
		repeat := c.lastUpsertLog[up.TunnelID] == fp
		c.lastUpsertLog[up.TunnelID] = fp
		c.mu.Unlock()
		lvl := slog.LevelInfo
		if repeat {
			lvl = slog.LevelDebug
		}
		c.logger.Log(ctx, lvl, "config push upsert",
			"tunnel_id", up.TunnelID, "name", up.Name, "type", string(up.Type),
			"domain", up.Domain, "remote_port", up.RemotePort)

		if !autoClaim || registry == nil {
			continue
		}
		go c.autoClaimOne(ctx, up)
	}

	for _, id := range push.CloseProxyIDs {
		// CloseProxyIDs from the edge currently carries the tunnel id
		// stringified. Best-effort parse — non-numeric ids belong to the
		// client-init close path and are handled by the pre-existing local
		// teardown.
		var tid int64
		for _, b := range []byte(id) {
			if b < '0' || b > '9' {
				tid = 0
				break
			}
			tid = tid*10 + int64(b-'0')
		}
		if tid <= 0 {
			continue
		}
		if tracker != nil {
			tracker.RemovePendingByTunnelID(tid)
		}
		c.mu.Lock()
		delete(c.lastUpsertLog, tid)
		c.mu.Unlock()
		c.logger.Info("config push close", "tunnel_id", tid)

		// Daemon mode: also tear down the local routing entry + tell the
		// edge to drop its proxy_id. The session-end cleanup would do
		// this eventually, but mid-session deletes from the console need
		// to take effect immediately.
		if !autoClaim || registry == nil {
			continue
		}
		if proxyID, ok := registry.ProxyIDByTunnelID(tid); ok {
			if err := c.CloseTunnel(proxyID, "console_delete"); err != nil {
				c.logger.Warn("send CLOSE_PROXY failed",
					"err", err, "proxy_id", proxyID, "tunnel_id", tid)
			}
			registry.RemoveProxy(proxyID)
			// Also remove from status tracker so the SPA's Tunnels page
			// doesn't keep a ghost row after console-side delete. The
			// pending-side row was already cleared above via
			// RemovePendingByTunnelID; this clears the active-side one.
			if tracker != nil {
				tracker.RemoveActiveTunnel(proxyID)
			}
		}
	}
}

// autoClaimOne runs the per-upsert claim flow in daemon mode. Idempotent:
// if the registry already has an entry for this tunnel_id (e.g., the
// catch-up push fired twice during reconnect storms), we skip without
// re-sending NEW_PROXY -- but we still need to clear the pending entry
// that handleConfigPush wrote a few lines earlier via UpsertPending,
// otherwise the status tracker accumulates one "pending:N" ghost row
// per repeat catch-up alongside the real "px-..." claimed row, and the
// Overview "活跃隧道" count drifts above the real Tunnels list count.
// beginClaim marks tunnelID as claim-in-flight. Returns false if another
// goroutine already holds it (a concurrent duplicate catch-up push), in which
// case the caller must NOT claim. The holder releases with endClaim.
func (c *Client) beginClaim(tunnelID int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.claiming[tunnelID] {
		return false
	}
	if c.claiming == nil {
		c.claiming = make(map[int64]bool)
	}
	c.claiming[tunnelID] = true
	return true
}

// endClaim releases the in-flight marker so a later push (e.g. a console edit,
// or the next reconnect) can claim the same tunnel again.
func (c *Client) endClaim(tunnelID int64) {
	c.mu.Lock()
	delete(c.claiming, tunnelID)
	c.mu.Unlock()
}

func (c *Client) autoClaimOne(ctx context.Context, up proto.UpsertProxy) {
	c.mu.Lock()
	registry := c.proxyResolver
	tracker := c.tracker
	c.mu.Unlock()
	if registry == nil {
		return
	}
	// In-flight de-dup: if another goroutine is already claiming this
	// tunnel_id (a duplicate catch-up push during a reconnect), skip — but
	// still clear the pending ghost this push's UpsertProxy wrote, exactly
	// like the idempotent-skip path below, so the Overview "active tunnels"
	// count doesn't drift above the real list.
	if !c.beginClaim(up.TunnelID) {
		if tracker != nil {
			tracker.RemovePendingByTunnelID(up.TunnelID)
		}
		c.logger.Debug("auto-claim skip — claim already in flight",
			"tunnel_id", up.TunnelID, "name", up.Name)
		return
	}
	defer c.endClaim(up.TunnelID)

	if pid, ok := registry.ProxyIDByTunnelID(up.TunnelID); ok {
		// Already registered. Distinguish an idempotent catch-up (same
		// upstream → skip, the historical behavior) from a console EDIT that
		// changed local_addr. We only re-home on a changed local target: the
		// public address (domain / remote_port) is not user-editable, and
		// config_json/security is enforced edge-side (no daemon re-dial). A
		// name-only edit also skips — the persisted row already carries the
		// new name, so the SPA table reflects it without disturbing traffic.
		reHome := false
		if look, lok := registry.(RegisteredTunnelLookup); lok {
			if cur, found := look.RegisteredTunnel(up.TunnelID); found && cur.LocalAddr != up.LocalAddr {
				reHome = true
			}
		}
		if !reHome {
			c.logger.Debug("auto-claim skip — already registered",
				"tunnel_id", up.TunnelID, "name", up.Name)
			// Same cleanup the success path does -- the just-arrived
			// UpsertPending wrote a pending:N row that's now redundant
			// (the active row already exists from the previous claim).
			if tracker != nil {
				tracker.RemovePendingByTunnelID(up.TunnelID)
			}
			return
		}
		// local_addr changed: close the old proxy on the ordered control
		// stream BEFORE the replacement NEW_PROXY below, so the edge frees
		// the route before we re-claim it (no CodeProxyDuplicate). New
		// connections then dial the new upstream.
		c.logger.Info("auto-claim re-home — local_addr changed",
			"tunnel_id", up.TunnelID, "name", up.Name, "local", up.LocalAddr)
		if err := c.CloseTunnel(pid, "console_update"); err != nil {
			c.logger.Warn("re-home CLOSE_PROXY failed",
				"err", err, "proxy_id", pid, "tunnel_id", up.TunnelID)
		}
		registry.RemoveProxy(pid)
		if tracker != nil {
			tracker.RemoveActiveTunnel(pid)
		}
		// fall through to register the new upstream
	}

	t := Tunnel{
		Name:       up.Name,
		Type:       up.Type,
		LocalAddr:  up.LocalAddr,
		Domain:     up.Domain,
		RemotePort: up.RemotePort,
	}
	assigned, err := c.RegisterTunnelLive(ctx, t, up.TunnelID)
	if err != nil {
		c.logger.Warn("auto-claim NEW_PROXY failed",
			"err", err, "tunnel_id", up.TunnelID, "name", up.Name)
		// Leave the entry as pending in the status page so the user sees
		// something happened. Operator log carries the real reason.
		return
	}
	registry.UpsertProxy(assigned.ProxyID, t)
	if idx, ok := registry.(TunnelIDIndexer); ok {
		idx.NoteTunnelID(up.TunnelID, assigned.ProxyID)
	}
	if tracker != nil {
		// Promote from "pending" to a real, claimed tunnel entry.
		tracker.RemovePendingByTunnelID(up.TunnelID)
		// Register in the active-tunnel table so subsequent piping
		// AddBytes/AddConnection calls find a key to land on (otherwise
		// the SPA's Tunnels/Overview pages show 0 conns + 0 bytes for
		// console-created tunnels — only CLI-launched tunnels would
		// have rows). See AddActiveTunnel in status/status.go for why
		// this is split from AddTunnel.
		tracker.AddActiveTunnel(
			assigned.ProxyID,
			up.TunnelID,
			up.Name,
			string(up.Type),
			up.LocalAddr,
			publicAddrFor(up.Type, assigned.Domain, assigned.RemotePort),
		)
	}
	c.logger.Info("auto-claimed tunnel",
		"tunnel_id", up.TunnelID, "name", up.Name,
		"proxy_id", assigned.ProxyID,
		"domain", assigned.Domain, "remote_port", assigned.RemotePort)
}

// publicAddrFor mirrors the format the single-tunnel CLI subcommands
// (http.go, tcp.go, udp.go, sni.go) stamp into TunnelInfo.PublicAddr.
// Kept here so daemon-mode auto-claim produces the same shape — the
// /status HTML render + Prometheus labels expect it.
//
// Note: TCP/UDP use the assigned RemotePort but have no edge host in
// this context (session pkg doesn't know its edge endpoint). The SPA
// ignores PublicAddr for the Tunnels list (it reads bff-console's
// domain/remote_port), so an empty-host scheme like "tcp://:5000" is
// fine; the legacy HTML page just shows it as ":5000".
func publicAddrFor(kind proto.ProxyKind, domain string, remotePort uint32) string {
	switch kind {
	case proto.ProxyKindHTTP:
		if domain != "" {
			return "http://" + domain
		}
	case proto.ProxyKindHTTPS, proto.ProxyKindSNI:
		if domain != "" {
			return "tls://" + domain
		}
	case proto.ProxyKindTCP:
		if remotePort != 0 {
			return fmt.Sprintf("tcp://:%d", remotePort)
		}
	case proto.ProxyKindUDP:
		if remotePort != 0 {
			return fmt.Sprintf("udp://:%d", remotePort)
		}
	}
	return ""
}

func (c *Client) handleNewConn(
	ctx context.Context,
	req *proto.NewConnRequest,
	resolve func(string) (Tunnel, bool),
) {
	t, ok := resolve(req.ProxyID)
	if !ok {
		c.logger.Warn("unknown proxy in NEW_CONN", "proxy_id", req.ProxyID)
		_ = c.ctrl.WritePayload(proto.FrameConnAck, &proto.ConnAck{
			ProxyID:  req.ProxyID,
			StreamID: req.StreamID,
			Error: proto.NewError(proto.CodeProxyNotFound,
				"calabi.err.proxy.not_found", "no such proxy on client"),
		})
		return
	}

	stream, err := c.mux.OpenDataStream(req.StreamID)
	if err != nil {
		c.logger.Warn("open data stream", "err", err)
		_ = c.ctrl.WritePayload(proto.FrameConnAck, &proto.ConnAck{
			ProxyID:  req.ProxyID,
			StreamID: req.StreamID,
			Error: proto.NewError(proto.CodeInternal,
				"calabi.err.internal", err.Error()),
		})
		return
	}
	defer stream.Close()

	if t.Type == proto.ProxyKindUDP {
		c.pumpUDP(req, t, stream)
		return
	}
	c.pumpTCP(req, t, stream)
}

// pumpTCP dials a TCP local upstream and io.Copy's bytes both ways.
// Covers http, https, tcp, and sni proxies — they all look like raw TCP
// to the local upstream.
//
// if a ConnectionInspector is attached, we wrap both halves of
// the copy in TeeReaders that fork bytes into the inspector's per-
// connection capture buffers, then call End() (which triggers HTTP
// parsing for http/https tunnels) when the conn closes.
func (c *Client) pumpTCP(req *proto.NewConnRequest, t Tunnel, stream io.ReadWriteCloser) {
	local, err := dialUpstream(t)
	if err != nil {
		c.logger.Info("local dial failed",
			"local", t.LocalAddr, "type", string(t.Type),
			"err", err, "proxy_id", req.ProxyID)
		_ = c.ctrl.WritePayload(proto.FrameConnAck, &proto.ConnAck{
			ProxyID:  req.ProxyID,
			StreamID: req.StreamID,
			Error: proto.NewError(proto.CodeLocalDialFailed,
				"calabi.err.local_dial", err.Error()),
		})
		return
	}
	defer local.Close()

	// Optimistic ACK -- bytes flow regardless.
	_ = c.ctrl.WritePayload(proto.FrameConnAck, &proto.ConnAck{
		ProxyID:  req.ProxyID,
		StreamID: req.StreamID,
	})

	c.mu.Lock()
	tracker := c.tracker
	inspector := c.inspector
	c.mu.Unlock()
	if tracker != nil {
		tracker.AddConnection(req.ProxyID)
	}

	var (
		inspHandle any
		reqBuf     io.Writer
		respBuf    io.Writer
	)
	if inspector != nil {
		inspHandle, reqBuf, respBuf = inspector.Begin(req.ProxyID, req.VisitorIP, string(t.Type))
	}

	c.logger.Info("piping",
		"proxy_id", req.ProxyID, "local", t.LocalAddr,
		"visitor", req.VisitorIP, "host", req.OriginalHost)

	// Optionally tee both halves into capture buffers. Bytes still
	// flow normally to/from local; tees just observe.
	streamSrc := io.Reader(stream)
	localSrc := io.Reader(local)
	if reqBuf != nil {
		streamSrc = io.TeeReader(streamSrc, reqBuf)
	}
	if respBuf != nil {
		localSrc = io.TeeReader(localSrc, respBuf)
	}

	// Wrap each write side with a meterWriter so the status tracker's
	// per-tunnel byte counters update WHILE bytes are flowing, not just
	// at connection close. Without this, long-lived connections (HTTP
	// keep-alive idle ~120s, SSE, WebSocket) leave the UI showing 0 B
	// until the conn finally tears down. See metered.go for the flush
	// scheduling rationale.
	//
	// proxyID is captured into local closures so the hot Write path
	// avoids the c.mu lock that req.ProxyID would imply if read live.
	proxyID := req.ProxyID
	var inFlush, outFlush func(int64)
	if tracker != nil {
		inFlush = func(n int64) { tracker.AddBytes(proxyID, "in", n) }
		outFlush = func(n int64) { tracker.AddBytes(proxyID, "out", n) }
	}
	meterIn := newMeterWriter(local, inFlush)
	meterOut := newMeterWriter(stream, outFlush)

	// Periodic flush ticker. Catches small writes that didn't hit the
	// inline 8KB threshold (e.g. a one-shot 200-byte HTTP request) so
	// the UI sees them within 250ms instead of waiting for conn close.
	// flushDone is closed by the cleanup path below, which races with
	// the ticker's own Flush calls — meterWriter.Flush is concurrency-
	// safe so the worst case is one extra (no-op) drain.
	flushDone := make(chan struct{})
	go func() {
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-flushDone:
				return
			case <-t.C:
				meterIn.Flush()
				meterOut.Flush()
			}
		}
	}()

	type result struct {
		dir   string
		bytes int64
		err   error
	}
	errCh := make(chan result, 2)
	go func() {
		n, e := io.Copy(meterIn, streamSrc)
		errCh <- result{"stream->local", n, e}
	}()
	go func() {
		n, e := io.Copy(meterOut, localSrc)
		errCh <- result{"local->stream", n, e}
	}()
	first := <-errCh
	// Drain the second result for cleanup so the goroutine exits.
	// Close both sides to unblock the other copy.
	_ = stream.Close()
	_ = local.Close()
	second := <-errCh
	close(flushDone)
	// Final drain after both halves stopped — the ticker may have
	// raced past the last Write; this catches the tail.
	meterIn.Flush()
	meterOut.Flush()

	var totalIn, totalOut int64
	for _, r := range []result{first, second} {
		switch r.dir {
		case "stream->local":
			totalIn = r.bytes
		case "local->stream":
			totalOut = r.bytes
		}
	}
	// NOTE: tracker.AddBytes is NOT called here with totalIn/totalOut.
	// The meterWriters already pushed those totals over the connection's
	// lifetime — adding them again would double-count. Inspector still
	// gets the final per-conn totals because it's a different state
	// (per-connection ring, not a running counter).
	if inspector != nil && inspHandle != nil {
		inspector.End(inspHandle, totalIn, totalOut, first.err)
	}
	c.logger.Info("piping closed",
		"proxy_id", req.ProxyID, "bytes_in", totalIn, "bytes_out", totalOut,
		"first_err", first.err)
}

// pumpUDP dials the local UDP upstream and copies framed datagrams.
//
// Each NEW_CONN owns one local UDP socket connected (via Dial) to the
// upstream — so we don't have to think about source address on the local
// side. Bytes flow:
//
//	stream  -> framed datagram -> WriteToUDP(local)   (visitor → upstream)
//	local   -> ReadFromUDP      -> framed -> stream   (upstream → visitor)
//
// EOF on the stream tears down both directions. The OpenProxyConn waiter
// on the edge holds onto this stream as part of the conntrack entry, so
// the edge's reaper closes us when the visitor goes idle.
func (c *Client) pumpUDP(req *proto.NewConnRequest, t Tunnel, stream io.ReadWriteCloser) {
	udpAddr, err := net.ResolveUDPAddr("udp", t.LocalAddr)
	if err != nil {
		_ = c.ctrl.WritePayload(proto.FrameConnAck, &proto.ConnAck{
			ProxyID:  req.ProxyID,
			StreamID: req.StreamID,
			Error: proto.NewError(proto.CodeLocalDialFailed,
				"calabi.err.local_dial", err.Error()),
		})
		return
	}
	local, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		c.logger.Info("udp local dial failed",
			"local", t.LocalAddr, "err", err, "proxy_id", req.ProxyID)
		_ = c.ctrl.WritePayload(proto.FrameConnAck, &proto.ConnAck{
			ProxyID:  req.ProxyID,
			StreamID: req.StreamID,
			Error: proto.NewError(proto.CodeLocalDialFailed,
				"calabi.err.local_dial", err.Error()),
		})
		return
	}
	defer local.Close()

	_ = c.ctrl.WritePayload(proto.FrameConnAck, &proto.ConnAck{
		ProxyID:  req.ProxyID,
		StreamID: req.StreamID,
	})

	c.mu.Lock()
	tracker := c.tracker
	c.mu.Unlock()
	if tracker != nil {
		tracker.AddConnection(req.ProxyID)
	}

	c.logger.Info("udp piping",
		"proxy_id", req.ProxyID, "local", t.LocalAddr,
		"visitor", req.VisitorIP)

	done := make(chan string, 2)

	// stream → local
	go func() {
		var bytes int64
		for {
			pkt, err := proto.ReadUDPDatagram(stream)
			if err != nil {
				done <- "stream->local"
				if tracker != nil {
					tracker.AddBytes(req.ProxyID, "in", bytes)
				}
				return
			}
			if len(pkt) == 0 {
				continue
			}
			if _, werr := local.Write(pkt); werr != nil {
				done <- "stream->local"
				if tracker != nil {
					tracker.AddBytes(req.ProxyID, "in", bytes)
				}
				return
			}
			bytes += int64(len(pkt))
		}
	}()

	// local → stream
	go func() {
		var bytes int64
		buf := make([]byte, 64*1024)
		for {
			n, _, err := local.ReadFromUDP(buf)
			if err != nil {
				done <- "local->stream"
				if tracker != nil {
					tracker.AddBytes(req.ProxyID, "out", bytes)
				}
				return
			}
			if err := proto.WriteUDPDatagram(stream, buf[:n]); err != nil {
				done <- "local->stream"
				if tracker != nil {
					tracker.AddBytes(req.ProxyID, "out", bytes)
				}
				return
			}
			bytes += int64(n)
		}
	}()

	first := <-done
	// Closing the stream and the local conn unblocks the other half.
	_ = stream.Close()
	_ = local.Close()
	c.logger.Info("udp piping direction finished",
		"dir", first, "proxy_id", req.ProxyID)
}
