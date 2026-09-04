package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	eventbus "github.com/calabi/calabi/apps/calabi-edge/internal/bus"
	"github.com/calabi/calabi/apps/calabi-edge/internal/session"
	proto "github.com/calabi/calabi/pkg/protocol"
)

// evictSubjectPrefix mirrors apps/identity-svc/internal/onlinecap.SubjectPrefix.
// Duplicated here so the two packages don't have to import each other.
const evictSubjectPrefix = "calabi.online_cap.evict"

// evictPayload is the JSON body of an evict event. Field names must match
// apps/identity-svc/internal/onlinecap.EvictPayload exactly.
type evictPayload struct {
	OrgID    int64  `json:"org_id"`
	ClientID int64  `json:"client_id"`
	Reason   string `json:"reason"`
}

// runEvictConsumer subscribes to calabi.online_cap.evict.<edge_node_id>
// and, for each message, looks up the live session by client_id and
// closes it. The matching client_session row in identity-svc will age
// out within one presence cycle (≤10s) once the session is gone.
//
// bus may be a noop (dev edge without NATS); in that case Subscribe
// returns no error but no messages will ever arrive — the consumer
// just idles until ctx is cancelled.
//
// edgeNodeID must match what the edge publishes in its presence
// reports — that's how identity-svc routes evicts back to the right
// edge.
func runEvictConsumer(
	ctx context.Context,
	logger *slog.Logger,
	bus eventbus.Bus,
	mgr *session.Manager,
	edgeNodeID int64,
) error {
	if bus == nil || mgr == nil || edgeNodeID == 0 {
		// No bus / no manager / no id — nothing to subscribe to.
		<-ctx.Done()
		return nil
	}
	subject := fmt.Sprintf("%s.%d", evictSubjectPrefix, edgeNodeID)
	log := logger.With("component", "evict-consumer", "subject", subject)

	sub, err := bus.Subscribe(subject, func(msg *eventbus.Msg) {
		var p evictPayload
		if err := json.Unmarshal(msg.Data, &p); err != nil {
			log.Warn("bad evict payload", "err", err, "data", string(msg.Data))
			return
		}
		sess := mgr.FindByDeviceID(p.ClientID)
		if sess == nil {
			// Already gone — either the client disconnected first, or
			// the evict reached a different edge by race. Either way the
			// next sweep will reconcile, so this is fine.
			log.Debug("evict: no live session", "client_id", p.ClientID, "org_id", p.OrgID)
			return
		}
		log.Info("evicting session for over-cap",
			"client_id", p.ClientID, "org_id", p.OrgID,
			"session_id", sess.ID, "reason", p.Reason)
		// Best-effort: tell the client *why* before we cut the conn.
		// The client's session.Run loop already handles FrameError as
		// "log + keep going"; the subsequent stream close drops it
		// into reconnect — at which point the new handshake re-validates
		// the bearer token (identity-svc.ValidateToken) and bounces a
		// suspended/deleted account, surfacing the reason to the user.
		//
		// The evict channel is shared by three producers, distinguished by
		// the reason prefix so the client sees the right code/message:
		//   - over-cap sweeper   → quota code (default)
		//   - admin account ban  → "account_suspended"/"account_deleted"
		//     → tenant-suspended code + a clear message (not a misleading
		//       "quota exceeded")
		//   - device delete      → reason="device_deleted": kept on the
		//     quota code with that exact message, which the daemon keys on
		//     to wipe its local creds. Don't disturb it.
		code := proto.CodeQuotaExceeded
		i18n := "calabi.err.quota.online_clients"
		reason := p.Reason
		switch {
		case strings.HasPrefix(p.Reason, "account_suspended"):
			code, i18n, reason = proto.CodeTenantSuspended, "calabi.err.account.suspended", "账号已被停用"
		case strings.HasPrefix(p.Reason, "account_deleted"):
			code, i18n, reason = proto.CodeTenantSuspended, "calabi.err.account.deleted", "账号已被删除"
		case reason == "":
			reason = "online client cap exceeded"
		}
		_ = sess.SendControl(proto.FrameError, proto.NewError(code, i18n, reason))
		_ = sess.Close()
	})
	if err != nil {
		return fmt.Errorf("evict subscribe: %w", err)
	}
	log.Info("evict consumer started")
	<-ctx.Done()
	if err := sub.Drain(); err != nil {
		log.Warn("evict drain failed", "err", err)
	}
	return nil
}
