package main

// platform_adapters.go holds the control-plane adapters that bridge the
// data-plane core interfaces (session.ProxyPersister, configclient.Applier,
// meshresolver sources) to the platform clients. It compiles in the DEFAULT
// build but is excluded by `-tags community` — every type here imports an
// internal/platform/* package, so none of it links into the community binary.

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/calabi/calabi/apps/calabi-edge/internal/meshresolver"
	"github.com/calabi/calabi/apps/calabi-edge/internal/platform/configclient"
	"github.com/calabi/calabi/apps/calabi-edge/internal/platform/identity"
	"github.com/calabi/calabi/apps/calabi-edge/internal/platform/tunnelstore"
	"github.com/calabi/calabi/apps/calabi-edge/internal/platform/usage"
	"github.com/calabi/calabi/apps/calabi-edge/internal/policy"
	"github.com/calabi/calabi/apps/calabi-edge/internal/session"
)

// tunnelIDIndex maps tunnel-svc row ids to local proxy ids so the
// configclient applier can unregister a proxy when a remote control-plane
// delete arrives. Safe for concurrent use.
type tunnelIDIndex struct{ m sync.Map }

func (t *tunnelIDIndex) set(tunnelID int64, proxyID string) { t.m.Store(tunnelID, proxyID) }
func (t *tunnelIDIndex) del(tunnelID int64)                 { t.m.Delete(tunnelID) }
func (t *tunnelIDIndex) get(tunnelID int64) (string, bool) {
	v, ok := t.m.Load(tunnelID)
	if !ok {
		return "", false
	}
	pid, ok := v.(string)
	return pid, ok
}

// tunnelPersisterAdapter satisfies session.ProxyPersister by translating
// the session-domain Proxy + Session into tunnel-svc CreateTunnel /
// ReportStatus / DeleteTunnel calls. All calls are best-effort: on
// transport failure we log and let the edge keep serving locally.
type tunnelPersisterAdapter struct {
	tc        *tunnelstore.Client
	logger    *slog.Logger
	edgeLabel string
	index     *tunnelIDIndex // populated so configclient applier can find proxy_id by tunnel_id
}

func (a *tunnelPersisterAdapter) OnProxyOpened(sess *session.Session, p *session.Proxy) (int64, error) {
	orgID, wsID := tunnelstore.ParseTenant(sess.TenantID, sess.WorkspaceID)

	// Phase D: NEW_PROXY carried claim_tunnel_id ⇒ the client is claiming
	// a console-pre-created row, not creating a fresh one. Try Claim first;
	// if it fails for a reason that's safe to retry as a fresh insert
	// (most commonly: the pending row got deleted between push and claim),
	// fall through to the normal Persist path so the proxy still works.
	if p.ClaimTunnelID != 0 {
		res, err := a.tc.Claim(context.Background(), tunnelstore.ClaimInput{
			TunnelID:      p.ClaimTunnelID,
			OrgID:         orgID,
			ClientID:      sess.DeviceID,
			EdgeNodeLabel: a.edgeLabel,
			Domain:        p.Domain,
			RemotePort:    int32(p.RemotePort),
		})
		if err == nil {
			a.tc.ReportStatus(context.Background(), res.TunnelID, "enabled", "")
			if a.index != nil {
				a.index.set(res.TunnelID, p.ID)
			}
			applyProxyPolicy(a.logger, p, res.ConfigJSON)
			a.logger.Info("claimed pending tunnel",
				"id", res.TunnelID, "proxy_id", p.ID, "type", string(p.Type))
			return res.TunnelID, nil
		}
		// an admin-disabled tunnel must HARD-FAIL here. Falling
		// through to Persist would mint a brand-new enabled row for the
		// same domain (reviving the tunnel) and then orphan-delete the
		// disabled row below — completely defeating the admin disable.
		// Return the error so handleNewProxy rolls back the local proxy and
		// the daemon surfaces a clear refusal instead of silently forwarding.
		if errors.Is(err, tunnelstore.ErrTunnelDisabled) {
			a.logger.Warn("claim refused: tunnel disabled (user or admin) — not reviving",
				"claim_tunnel_id", p.ClaimTunnelID, "proxy_id", p.ID,
				"type", string(p.Type), "domain", p.Domain)
			return 0, err
		}
		// a genuine ownership conflict (FailedPrecondition) must ALSO
		// hard-fail here. Falling through to Persist would mint a brand-new row
		// for this tunnel and orphan-delete the conflicting one — the exact loop
		// that left bursts of identical deleted TCP rows when a port tunnel
		// bounced between same-region edges. tunnel-svc now re-homes
		// same-client/same-region claims in place (base_domain match), so
		// reaching this branch means a real conflict (cross-region, different
		// client, or a still-live previous owner) that must surface — not be
		// papered over with a duplicate.
		if errors.Is(err, tunnelstore.ErrClaimConflict) {
			a.logger.Warn("claim refused: tunnel owned by another edge / conflict — not minting duplicate",
				"claim_tunnel_id", p.ClaimTunnelID, "proxy_id", p.ID,
				"type", string(p.Type), "domain", p.Domain, "remote_port", p.RemotePort)
			return 0, err
		}
		// log every relevant scoping field at WARN so operators
		// can tell from the log whether the failure was NotFound, an
		// Org/Client precondition, or a Unique-index collision.
		a.logger.Warn("claim failed, falling back to Persist — orphan source row will be cleaned up post-Persist",
			"claim_tunnel_id", p.ClaimTunnelID,
			"err", err,
			"proxy_id", p.ID,
			"org_id", orgID,
			"workspace_id", wsID,
			"device_id", sess.DeviceID,
			"edge_node_id", a.tc.EdgeNodeID(),
			"edge_node_label", a.edgeLabel,
			"type", string(p.Type),
			"name", p.Name,
			"domain", p.Domain,
			"remote_port", p.RemotePort,
		)
	}

	res, err := a.tc.Persist(context.Background(), tunnelstore.PersistInput{
		OrgID:       orgID,
		WorkspaceID: wsID,
		ClientID:    sess.DeviceID,
		Name:        p.Name,
		Type:        string(p.Type),
		LocalAddr:   p.LocalAddr,
		Domain:      p.Domain,
		RemotePort:  int32(p.RemotePort),
	})
	if err != nil {
		// with the (edge_node_id, remote_port) unique check
		// now firing on the Persist path (CreateTunnel respects req.
		// edge_node_id), AlreadyExists here means a real port collision
		// — likely a race where two NEW_PROXYs landed on the same
		// freshly-restarted edge before its port pool was DB-seeded, or
		// a misuse where the same port was requested twice. Return the
		// error so handleNewProxy rolls back the local proxy and
		// surfaces it in NEW_PROXY_RESP. Without this rollback the
		// proxy would serve traffic locally but have no DB row → SPA
		// ghost + quota miscount.
		a.logger.Warn("persist tunnel failed",
			"err", err, "proxy_id", p.ID, "type", string(p.Type),
			"remote_port", p.RemotePort, "edge_node_id", a.tc.EdgeNodeID())
		return 0, err
	}
	if res.TunnelID != 0 {
		// Mark online via ReportStatus so the row gets last_seen_at
		// stamped right at registration time.
		a.tc.ReportStatus(context.Background(), res.TunnelID, "enabled", "")
		if a.index != nil {
			a.index.set(res.TunnelID, p.ID)
		}
	}
	// orphan cleanup: when we got here via fallback (Claim
	// failed → Persist created a new row), the original row at
	// ClaimTunnelID is stranded — soft-delete it. Safe because the
	// only path setting ClaimTunnelID is the daemon's autoClaimOne,
	// which fires only after a CONFIG_PUSH that's already filtered to
	// sess.DeviceID == row.client_id; we're cleaning up our own orphan.
	if p.ClaimTunnelID != 0 && res.TunnelID != 0 && res.TunnelID != p.ClaimTunnelID {
		a.logger.Warn("cleaning up orphan row left by failed Claim",
			"orphan_tunnel_id", p.ClaimTunnelID,
			"new_tunnel_id", res.TunnelID,
			"proxy_id", p.ID)
		a.tc.Delete(context.Background(), p.ClaimTunnelID)
	}
	applyProxyPolicy(a.logger, p, res.ConfigJSON)
	a.logger.Debug("persisted tunnel", "id", res.TunnelID, "proxy_id", p.ID)
	return res.TunnelID, nil
}

// applyProxyPolicy parses the tunnel row's server-authoritative config_json
// into the proxy's enforced security policy (IP allowlist, …). The blob comes
// from tunnel-svc's response — never from the daemon — so a tampered client
// can't strip its own restrictions. Best-effort + fail-open: a malformed blob
// logs and leaves Policy nil (allow all) so a config glitch never blackholes a
// tunnel. See apps/calabi-edge/internal/policy +
//
// Platform-only: a standalone edge applies client-supplied policy directly in
// session/controlloop.go, not via this server-authoritative path.
func applyProxyPolicy(logger *slog.Logger, p *session.Proxy, configJSON string) {
	pol, err := policy.Parse(configJSON)
	if err != nil {
		logger.Warn("parse tunnel security policy failed; serving without policy",
			"proxy_id", p.ID, "domain", p.Domain, "err", err)
		return
	}
	p.SetPolicy(pol)
	if pol.HasIPRules() {
		logger.Info("tunnel security policy applied",
			"proxy_id", p.ID, "domain", p.Domain,
			"ip_allow", len(pol.IPAllow), "ip_deny", len(pol.IPDeny))
	}
}

func (a *tunnelPersisterAdapter) OnProxyClosed(sess *session.Session, p *session.Proxy, reason string) {
	if p.TunnelID == 0 {
		return
	}
	// We mark offline rather than delete: deleting on every session
	// drop would race against quick client reconnects.
	a.tc.ReportStatus(context.Background(), p.TunnelID, "offline", reason)
	if a.index != nil {
		a.index.del(p.TunnelID)
	}
}

// routeApplier wires configclient.Applier into the local router.
//
// scope:
//   - delete + local edge: unregister via registrar (achieves cross-process
//     "calabi delete" → all edges drop the route)
//   - upsert + local edge: no-op (the route is already in our local map
//     from the live client session; tunnel-svc is just confirming what we
//     already know)
//   - any kind + remote edge: log only; will route visitor traffic to
//     the right edge instead of returning 404
//
// Phase C additions:
//   - upsert (any edge) + Route.ClientID matches a live session on this
//     edge: forward the upsert to the client over CONFIG_PUSH so the
//     client's UI / future daemon can react. Routes with edge_node_id=0
//     (console-initiated, no edge claimed yet) reach every edge via
//     the relaxed hub filter; only the edge holding the matching client
//     session will actually forward.
type routeApplier struct {
	edgeNodeID int64
	registrar  session.ProxyRegistrar
	manager    *session.Manager
	index      *tunnelIDIndex
	logger     *slog.Logger
	// baseDomain is this edge's HTTPListener.BaseDomain, used to resolve a
	// console tunnel's requested subdomain PREFIX to <prefix>.<base> before
	// forwarding the CONFIG_PUSH to the daemon (Phase 2).
	baseDomain string
}

func (a *routeApplier) OnSnapshot(routes []configclient.Route) {
	// log only. reconciles snapshot against local
	// router (delete locally-owned routes that the snapshot doesn't
	// mention, hint at remote routes).
	a.logger.Debug("snapshot received", "routes", len(routes))
}

func (a *routeApplier) OnLocalDelta(d configclient.Delta) {
	switch d.Kind {
	case "delete":
		proxyID, ok := a.index.get(int64(d.Route.ID))
		if !ok {
			// Either we never knew this tunnel (stale delta after restart)
			// or it was already unregistered.
			a.logger.Debug("local delete: proxy_id not found in index",
				"tunnel_id", d.Route.ID)
		} else {
			a.registrar.UnregisterByProxyID(proxyID)
			a.index.del(int64(d.Route.ID))
			a.logger.Info("local delete applied",
				"tunnel_id", d.Route.ID, "proxy_id", proxyID, "domain", d.Route.Domain)
		}
	case "upsert":
		// Route already owned locally — nothing to do for the router itself,
		// BUT hot-update the live proxy's security policy from the edited
		// config_json so a console/SPA IP-allowlist change takes effect
		// WITHOUT a reconnect. Server-authoritative: the blob comes from
		// config-svc (tunnel-svc's row), not the daemon.
		a.applyPolicyDelta(d)
	}
	a.forwardToClient(d)
}

// applyPolicyDelta hot-swaps a live proxy's security policy when its tunnel's
// config_json changes. No-op (and safe) when the tunnel isn't currently served
// by this edge — the proxy then picks up the policy at its next registration.
// Best-effort + fail-open: a malformed blob keeps the current policy.
func (a *routeApplier) applyPolicyDelta(d configclient.Delta) {
	if a.manager == nil || a.index == nil {
		return
	}
	proxyID, ok := a.index.get(int64(d.Route.ID))
	if !ok {
		return // not live here yet — registration will apply the policy
	}
	pol, err := policy.Parse(d.Route.ConfigJSON)
	if err != nil {
		a.logger.Warn("hot policy update: parse config_json failed; keeping current",
			"tunnel_id", d.Route.ID, "err", err)
		return
	}
	// Find the live session that owns this proxy (the tunnel's client), then
	// swap the policy atomically — listeners reading it never see a torn value.
	var target *session.Session
	if d.Route.ClientID > 0 {
		a.manager.All(func(s *session.Session) bool {
			if s.DeviceID == d.Route.ClientID {
				target = s
				return false
			}
			return true
		})
	}
	if target == nil {
		return
	}
	p := target.Proxy(proxyID)
	if p == nil {
		return
	}
	p.SetPolicy(pol)
	// Cut any ESTABLISHED keep-alive connection the new policy now denies, so a
	// fresh denylist entry takes effect immediately instead of only on the next
	// new connection (a browser holds its connection open otherwise).
	cut := target.CloseProxyConnsDenied(proxyID, pol)
	a.logger.Info("hot policy update applied",
		"tunnel_id", d.Route.ID, "proxy_id", proxyID,
		"has_ip_rules", pol.HasIPRules(), "conns_cut", cut)
}

func (a *routeApplier) OnRemoteDelta(d configclient.Delta) {
	a.logger.Debug("remote delta noted",
		"kind", d.Kind, "edge", d.Route.EdgeNodeID,
		"tunnel_id", d.Route.ID, "domain", d.Route.Domain)
	// Phase C: even a "remote" route may belong to a client currently
	// connected to THIS edge (unassigned edge_node_id=0 routes land here).
	a.forwardToClient(d)
}

// forwardToClient finds the live session whose DeviceID matches
// d.Route.ClientID and sends a CONFIG_PUSH frame announcing the
// upsert/delete. No-op when no matching session, when manager isn't
// wired, or when the route carries no client_id.
func (a *routeApplier) forwardToClient(d configclient.Delta) {
	if a.manager == nil || d.Route.ClientID <= 0 {
		return
	}
	var target *session.Session
	a.manager.All(func(s *session.Session) bool {
		if s.DeviceID == d.Route.ClientID {
			target = s
			return false // stop iteration
		}
		return true
	})
	if target == nil {
		return
	}
	push := buildConfigPushFromDelta(d, a.baseDomain)
	if push == nil {
		return
	}
	if err := target.SendControl(protocolFrameConfigPush, push); err != nil {
		a.logger.Debug("forward to client failed",
			"client_id", d.Route.ClientID, "err", err)
		return
	}
	a.logger.Info("delta forwarded to client",
		"client_id", d.Route.ClientID,
		"session_id", target.ID,
		"kind", d.Kind, "tunnel_id", d.Route.ID)
}

// runDenySweeper pumps state from the usage deny hook into the live
// session set. Runs every 2s — denial signals are NATS-driven so this
// is just a "did the deny set change, propagate to sessions" loop.
//
// Sessions whose tenantID parses to an org_id present in the hook get
// SetBlockReason(reason); on Allow the block is cleared.
func runDenySweeper(ctx context.Context, logger *slog.Logger, mgr *session.Manager, hook *usage.DenyHook) error {
	if hook == nil {
		<-ctx.Done()
		return nil
	}
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			mgr.All(func(s *session.Session) bool {
				org, err := strconvAtoi64(s.TenantID)
				if err != nil || org <= 0 {
					return true
				}
				blocked, reason := hook.IsBlocked(org)
				if blocked {
					if was, _ := s.IsBlocked(); !was {
						logger.Info("session blocked by usage deny",
							"session_id", s.ID, "org", org, "reason", reason)
					}
					s.SetBlockReason(reason)
				} else {
					if was, _ := s.IsBlocked(); was {
						logger.Info("session unblocked",
							"session_id", s.ID, "org", org)
					}
					s.SetBlockReason("")
				}
				return true
			})
		}
	}
}

// usageReportInterval reads CALABI_USAGE_REPORT_INTERVAL_MS to override
// the usage reporter cadence. Unset / 0 / invalid keeps the
// usage.DefaultReportInterval (60s). The metering bucket is still
// per-minute, so 60s is the finest useful setting; 300s ≈ ÷5 cost.
func usageReportInterval(logger *slog.Logger) time.Duration {
	v := os.Getenv("CALABI_USAGE_REPORT_INTERVAL_MS")
	if v == "" {
		return 0
	}
	ms, err := strconvAtoi64(v)
	if err != nil || ms <= 0 {
		logger.Warn("ignoring invalid CALABI_USAGE_REPORT_INTERVAL_MS", "value", v)
		return 0
	}
	d := time.Duration(ms) * time.Millisecond
	logger.Info("usage report interval overridden", "interval", d.String())
	return d
}

// meshOwnerSource adapts *tunnelstore.Client to meshresolver.OwnerSource,
// mapping the tunnelstore.OwnerEntry wire shape to meshresolver.Owner.
// Works in both cluster mode and bff-edge mode (bff-edge proxies
// ResolveOwners + ListEdges as of 2026-06-03, so same-region mesh runs
// over the bff-edge gateway too).
type meshOwnerSource struct{ tc *tunnelstore.Client }

func (m meshOwnerSource) ResolveOwners(ctx context.Context, baseDomain, knownGen string) ([]meshresolver.Owner, string, bool, error) {
	rows, gen, unchanged, err := m.tc.ResolveOwners(ctx, baseDomain, knownGen)
	if err != nil {
		return nil, "", false, err
	}
	if unchanged {
		return nil, gen, true, nil
	}
	out := make([]meshresolver.Owner, 0, len(rows))
	for _, r := range rows {
		out = append(out, meshresolver.Owner{Domain: r.Domain, EdgeNodeID: r.EdgeNodeID})
	}
	return out, gen, false, nil
}

// meshEdgeDirectory adapts *identity.Verifier to meshresolver.EdgeDirectory.
type meshEdgeDirectory struct{ v *identity.Verifier }

func (m meshEdgeDirectory) ListEdges(ctx context.Context, region string) ([]meshresolver.Edge, error) {
	rows, err := m.v.ListEdges(ctx, region)
	if err != nil {
		return nil, err
	}
	out := make([]meshresolver.Edge, 0, len(rows))
	for _, e := range rows {
		out = append(out, meshresolver.Edge{
			EdgeNodeID:   e.EdgeNodeID,
			Region:       e.Region,
			InternalAddr: e.InternalAddr,
			Healthy:      e.Healthy,
		})
	}
	return out, nil
}
