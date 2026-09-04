package main

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/calabi/calabi/apps/calabi-edge/internal/platform/identity"
	"github.com/calabi/calabi/apps/calabi-edge/internal/session"
)

// defaultPresenceInterval is the fallback heartbeat cadence used when
// the operator doesn't override it via edge.yaml `presence.interval_seconds`.
// 15s pairs with the 35s default freshness window in
// identity-svc.GetClientStatuses (≈2× heartbeat + slack).
//
// History: hard-coded 10s and that turned out to dominate PG QPS at
// 10k clients. X1 batched the upserts (one tx per tick) and X2
// (this change) made the cadence operator-tunable so prod can run at
// 15-20s without code changes.
const defaultPresenceInterval = 15 * time.Second

// runPresenceReporter walks the live session set every `interval`
// and uploads the active device_ids to identity-svc. Sessions whose
// AUTH frame carried no device_id are
// silently skipped — the console will simply show those rows as offline,
// which matches user expectation for clients that never registered.
//
// interval=0 falls back to defaultPresenceInterval. Values below 5s are
// clamped at the config layer (see PresenceConfig.PresenceInterval).
//
// identityCli is optional; nil disables reporting entirely (dev path
// where identity-svc isn't wired). The loop exits when ctx is cancelled.
//
// kick is an optional channel: any send wakes the loop and
// triggers an immediate publish before going back to the regular tick.
// Wired by main to the listener's session-close hook so a daemon
// disconnect propagates within seconds — without this the row would
// sit at "online" until the freshness window expires (~50s p99).
// Buffered so kicks coalesce: multiple sessions ending in the same
// tick window result in a single publish, not a flood.
func runPresenceReporter(
	ctx context.Context,
	logger *slog.Logger,
	identityCli *identity.Verifier,
	mgr *session.Manager,
	edgeNodeID int64,
	edgeNodeLabel string,
	interval time.Duration,
	kick <-chan struct{},
) error {
	if identityCli == nil {
		// No identity-svc — nothing to report to.
		<-ctx.Done()
		return nil
	}
	if interval <= 0 {
		interval = defaultPresenceInterval
	}
	log := logger.With("component", "presence-reporter", "edge", edgeNodeID, "interval", interval)
	t := time.NewTicker(interval)
	defer t.Stop()

	publish := func() {
		entries := make([]identity.PresenceEntry, 0, 16)
		mgr.All(func(s *session.Session) bool {
			if s.DeviceID > 0 {
				// TenantID is the numeric org_id stringified at handshake
				// (see identity.Verifier.Verify). Parse back to int64; on
				// parse failure we still report client_id but with
				// org_id=0 — identity-svc tolerates that (legacy shape)
				// and just won't count it toward the online cap.
				var orgID int64
				if v, err := strconv.ParseInt(strings.TrimSpace(s.TenantID), 10, 64); err == nil {
					orgID = v
				}
				entries = append(entries, identity.PresenceEntry{
					ClientID:  s.DeviceID,
					OrgID:     orgID,
					ConnEpoch: s.ConnEpoch,
				})
			}
			return true
		})
		// Always report — empty set is a valid signal ("nobody home").
		// identity-svc tolerates the empty list AND uses
		// it as the trigger to clear any stale rows still stamped with
		// this edge_node_id.
		if err := identityCli.ReportPresence(ctx, edgeNodeID, edgeNodeLabel, entries); err != nil {
			log.Debug("presence report failed", "err", err, "n", len(entries))
			return
		}
		if len(entries) > 0 {
			log.Debug("presence reported", "n", len(entries))
		}
	}

	// Fire once immediately so a fresh edge advertises its sessions
	// without waiting a full interval.
	publish()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			publish()
		case <-kick:
			// Drain any other pending kicks so a burst of session-end
			// events collapses to one publish instead of N.
		drain:
			for {
				select {
				case <-kick:
				default:
					break drain
				}
			}
			publish()
		}
	}
}
