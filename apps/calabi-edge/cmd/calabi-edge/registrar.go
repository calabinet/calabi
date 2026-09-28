// edge self-registration loop.
//
// The edge calls identity-svc.RegisterEdgeNode on boot + every
// `registerInterval` while running so daemons doing ListEdges always
// see a fresh snapshot. The cadence pairs with identity-svc's default
// 90s freshness window (3× heartbeat).
package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/calabinet/calabi/apps/calabi-edge/internal/platform/identity"
	"github.com/calabinet/calabi/apps/calabi-edge/internal/session"
)

const registerInterval = 30 * time.Second

// registerWarnEvery bounds how often a STILL-failing heartbeat says so again.
// Ten minutes: often enough that someone opening the log an hour into the
// outage sees it without scrolling, rare enough that it is not the only thing
// in the file after a week.
const registerWarnEvery = 10 * time.Minute

// heartbeatLog decides what a repeating publish is allowed to say.
//
// Both loops used to log every failure at DEBUG, which at the default level is
// not logging at all. 2026-09-25 that hid a real one for weeks: bff-edge held an
// empty coord token, so every relay self-registration was refused, and the only
// symptom anyone could see was that self-hosted relays never appeared in their
// org — the node itself looked healthy and said nothing.
//
// Debug was not an unreasonable choice, though, and the reason matters for what
// replaces it: these run every 30 seconds forever, and a warning every 30
// seconds is filtered within a day, taking the one that mattered with it. So the
// rule here is that STATE CHANGES are loud and steady state is quiet — the first
// failure warns, the repeats go to debug with a reminder every
// registerWarnEvery, and recovery says how long it was down.
type heartbeatLog struct {
	log  *slog.Logger
	what string // "edge" / "relay" — the thing being registered
	// hurts names the consequence, in the operator's terms. A registrar that
	// says only "failed" leaves the reader to work out whether it matters.
	hurts string

	failing  bool
	since    time.Time
	attempts int
	lastWarn time.Time
}

func (h *heartbeatLog) failed(err error) {
	now := time.Now()
	h.attempts++
	switch {
	case !h.failing:
		h.failing, h.since, h.attempts, h.lastWarn = true, now, 1, now
		h.log.Warn("register "+h.what+" failed", "err", err, "consequence", h.hurts,
			"retrying_every", registerInterval)
	case now.Sub(h.lastWarn) >= registerWarnEvery:
		h.lastWarn = now
		h.log.Warn("register "+h.what+" still failing", "err", err, "consequence", h.hurts,
			"failing_for", now.Sub(h.since).Round(time.Second), "attempts", h.attempts)
	default:
		h.log.Debug("register "+h.what+" failed", "err", err, "attempts", h.attempts)
	}
}

func (h *heartbeatLog) ok(args ...any) {
	if h.failing {
		h.log.Info("register "+h.what+" recovered",
			"was_failing_for", time.Since(h.since).Round(time.Second), "attempts", h.attempts)
		h.failing, h.attempts = false, 0
	}
	h.log.Debug(h.what+" registered", args...)
}

// runEdgeRegistrar re-publishes `reg` every registerInterval, refreshing
// ActiveClients each tick (everything else is static for the process).
//
// The identity is passed as a struct, not as a positional list: it had grown to
// five same-typed strings in a row (label / region / public / internal / class)
// and base_domain would have made six — one transposed argument at the single
// call site and the directory would carry silently wrong data.
func runEdgeRegistrar(
	ctx context.Context,
	logger *slog.Logger,
	identityCli *identity.Verifier,
	mgr *session.Manager,
	reg identity.EdgeRegistration,
) error {
	if identityCli == nil {
		<-ctx.Done()
		return nil
	}
	hb := &heartbeatLog{
		log:   logger.With("component", "edge-registrar", "edge", reg.EdgeNodeID),
		what:  "edge",
		hurts: "this node goes stale in the edge directory; clients doing ListEdges stop being offered it",
	}
	t := time.NewTicker(registerInterval)
	defer t.Stop()

	publish := func() {
		var n int
		if mgr != nil {
			mgr.All(func(*session.Session) bool {
				n++
				return true
			})
		}
		tick := reg
		tick.ActiveClients = int32(n)
		if err := identityCli.RegisterEdgeNode(ctx, tick); err != nil {
			hb.failed(err)
			return
		}
		hb.ok("active_clients", n)
	}
	publish()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			publish()
		}
	}
}

// runRelayRegistrar self-registers this node's RELAY endpoint into the org DERP
// map on boot + every registerInterval, mirroring runEdgeRegistrar exactly
// (edge/derp merge-B): the relay appears automatically, just like the edge.
// register does one idempotent upsert (coord only re-pushes netmaps when the map
// actually changes, so a steady-state heartbeat is cheap). nil register =
// not wired (self-hosted / cluster mode / no org / no relay label) → the loop
// idles until shutdown.
func runRelayRegistrar(ctx context.Context, logger *slog.Logger, register func(context.Context) error) error {
	if register == nil {
		<-ctx.Done()
		return nil
	}
	hb := &heartbeatLog{
		log:   logger.With("component", "relay-registrar"),
		what:  "relay",
		hurts: "this relay stays out of the organization's DERP map; its devices are never offered it",
	}
	t := time.NewTicker(registerInterval)
	defer t.Stop()
	publish := func() {
		if err := register(ctx); err != nil {
			hb.failed(err)
			return
		}
		hb.ok()
	}
	publish()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			publish()
		}
	}
}
