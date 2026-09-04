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

	"github.com/calabi/calabi/apps/calabi-edge/internal/platform/identity"
	"github.com/calabi/calabi/apps/calabi-edge/internal/session"
)

const registerInterval = 30 * time.Second

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
	log := logger.With("component", "edge-registrar", "edge", reg.EdgeNodeID)
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
			log.Debug("register edge failed", "err", err)
			return
		}
		log.Debug("edge registered", "active_clients", n)
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
	log := logger.With("component", "relay-registrar")
	t := time.NewTicker(registerInterval)
	defer t.Stop()
	publish := func() {
		if err := register(ctx); err != nil {
			log.Debug("register relay failed", "err", err)
			return
		}
		log.Debug("relay registered")
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
