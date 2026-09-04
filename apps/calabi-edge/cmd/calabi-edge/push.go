package main

import (
	"context"
	"log/slog"
	"strconv"
	"strings"

	"github.com/calabi/calabi/apps/calabi-edge/internal/platform/configclient"
	"github.com/calabi/calabi/apps/calabi-edge/internal/session"
	"github.com/calabi/calabi/apps/calabi-edge/internal/platform/tunnelstore"
	proto "github.com/calabi/calabi/pkg/protocol"
)

// resolveProxyHost returns the public host the daemon should request in
// NEW_PROXY for a console-created http/https tunnel (Phase 2):
//   - an explicit custom domain, if set; else
//   - <subdomain>.<base> when the user requested a platform subdomain
//     prefix and this edge advertises a base_domain; else
//   - "" so the edge auto-allocates u%06d.<base> at NEW_PROXY time.
//
// The prefix→host resolution happens HERE (edge-side) because the edge
// knows its own region base_domain; the daemon then sends the full host
// as Domain and the existing explicit-domain NEW_PROXY path registers it,
// so neither the wire frame nor the daemon needs a subdomain field.
func resolveProxyHost(domain, subdomain, base string) string {
	if strings.TrimSpace(domain) != "" {
		return domain
	}
	subdomain = strings.ToLower(strings.TrimSpace(subdomain))
	base = strings.TrimSpace(base)
	if subdomain != "" && base != "" {
		return subdomain + "." + base
	}
	return ""
}

// protocolFrameConfigPush is the FrameType for runtime config pushes —
// aliased so route-applier code doesn't have to import the protocol
// package directly for a single constant. Phase C uses it to surface
// console-initiated upserts on the client side.
const protocolFrameConfigPush = proto.FrameConfigPush

// buildConfigPushFromDelta projects a config-svc Delta into the wire
// ConfigPush payload. Upserts go into upsert_proxies; deletes go into
// close_proxy_ids (using the tunnel_id as a string so the client can
// match against its own per-tunnel state).
func buildConfigPushFromDelta(d configclient.Delta, baseDomain string) *proto.ConfigPush {
	switch d.Kind {
	case "upsert":
		return &proto.ConfigPush{
			UpsertProxies: []proto.UpsertProxy{{
				TunnelID:   int64(d.Route.ID),
				Name:       d.Route.Name,
				Type:       proto.ProxyKind(d.Route.Type),
				LocalAddr:  d.Route.LocalAddr,
				// Phase 2: resolve a requested subdomain prefix to
				// <prefix>.<this edge base> so the daemon's NEW_PROXY
				// pins it in this region.
				Domain:     resolveProxyHost(d.Route.Domain, d.Route.Subdomain, baseDomain),
				RemotePort: uint32(d.Route.RemotePort),
			}},
		}
	case "delete":
		// We don't have the proxy_id on the delete path (the client uses
		// proxy_id, not tunnel_id, for its local map). Best-effort: send
		// the tunnel-id as a string and let the client match by metadata.
		// Real-time delete is fully wired via the existing edge-side
		// router teardown; this is informational for the client UI.
		return &proto.ConfigPush{
			CloseProxyIDs: []string{itoaInt(d.Route.ID)},
		}
	default:
		return nil
	}
}

// makePostHandshake returns the per-session catch-up hook called by the
// control listener right after AUTH succeeds. When wired (tunnel-svc
// available + session announced a DeviceID), it fetches every tunnel
// owned by this client and pushes them down as a single CONFIG_PUSH so
// the client's status page is consistent with the server view even
// across disconnects. Console-created "allow_offline" tunnels also
// reach the client this way the first time it connects.
//
// Returns nil when there's no tunnel-svc client — the hook is optional
// at the listener level.
func makePostHandshake(logger *slog.Logger, tc *tunnelstore.Client, baseDomain string) func(context.Context, *session.Session) {
	if tc == nil {
		return nil
	}
	log := logger.With("component", "post-handshake")
	return func(ctx context.Context, sess *session.Session) {
		if sess == nil || sess.DeviceID <= 0 {
			return
		}
		orgID, _ := strconv.ParseInt(sess.TenantID, 10, 64)
		if orgID <= 0 {
			return
		}
		tunnels, err := tc.ListByClient(ctx, orgID, sess.DeviceID)
		if err != nil {
			log.Debug("catch-up list failed", "err", err, "client", sess.DeviceID)
			return
		}
		if len(tunnels) == 0 {
			return
		}
		push := &proto.ConfigPush{
			// Mark this as the authoritative full list so the client
			// reconciles its snapshot — without this, any tunnel the
			// client got an upsert for, then a delete it missed (e.g.
			// while briefly disconnected), would stay in the snapshot
			// forever and inflate the "活跃隧道" count. See ConfigPush
			// docs in pkg/protocol/payload.go for the wire contract.
			FullSync:      true,
			UpsertProxies: make([]proto.UpsertProxy, 0, len(tunnels)),
		}
		for _, t := range tunnels {
			push.UpsertProxies = append(push.UpsertProxies, proto.UpsertProxy{
				TunnelID:  t.GetMeta().GetId(),
				Name:      t.GetName(),
				Type:      proto.ProxyKind(t.GetType()),
				LocalAddr: t.GetLocalAddr(),
				// Phase 2: resolve a requested subdomain prefix to
				// <prefix>.<this edge base> for catch-up pushes too.
				Domain:     resolveProxyHost(t.GetDomain(), t.GetSubdomain(), baseDomain),
				RemotePort: uint32(t.GetRemotePort()),
			})
		}
		if err := sess.SendControl(proto.FrameConfigPush, push); err != nil {
			log.Debug("catch-up push failed", "err", err, "client", sess.DeviceID)
			return
		}
		log.Info("catch-up pushed",
			"client_id", sess.DeviceID,
			"session_id", sess.ID,
			"n", len(tunnels))
	}
}

// itoaInt avoids pulling strconv just for a one-shot int→string.
func itoaInt(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
