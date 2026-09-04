package main

// wiring.go holds the build-tag-agnostic seam between the data-plane core and
// the control-plane wiring. A build-tagged wirePlatform implements these types,
// and run() consumes the returned bundle without importing a single platform
// package.

import (
	"context"
	"crypto/tls"
	"io"

	"github.com/calabi/calabi/apps/calabi-edge/internal/config"
	"github.com/calabi/calabi/apps/calabi-edge/internal/listener"
	"github.com/calabi/calabi/apps/calabi-edge/internal/router"
	"github.com/calabi/calabi/apps/calabi-edge/internal/session"
)

// platformInputs are the core data-plane objects the platform wiring attaches
// to: it seeds the allocator/port-pool from tunnel-svc, registers routes from
// config-svc deltas, and reports presence/usage for the live session set. They
// are all created in run() before wirePlatform is called, so the core stands up
// fully on its own and the control plane is a pure additive layer.
type platformInputs struct {
	cfg          config.Config
	mgr          *session.Manager
	domains      *router.SubdomainAllocator
	ports        *router.PortPool
	registrar    session.ProxyRegistrar
	edgeID       int64
	presenceKick <-chan struct{}
}

// namedRunner is a background goroutine the platform layer asks run() to launch
// alongside the core listeners, labelled for the shared error channel.
type namedRunner struct {
	name string
	run  func(context.Context) error
}

// platformDeps is everything the platform build wires up and the core run()
// consumes. Every field is optional: a community build returns an all-nil
// bundle (bar a dev-friendly bandwidth resolver) and the data plane runs fully
// standalone. The interface-typed fields plug straight into the listener
// options; nil short-circuits to the dev/standalone behaviour already baked
// into the listeners (admit-all, no persistence, no quota, 502-on-miss).
type platformDeps struct {
	// controlPlaneWired reports whether a real control plane (identity /
	// tunnel / bff-edge) was dialed. Feeds cfg.TrustsClientPolicy so a BYOI /
	// managed edge never trusts client-supplied security policy. Always false
	// in a community build.
	controlPlaneWired bool

	verifier          session.TokenVerifier // nil → run() keeps the static-token verifier
	persister         session.ProxyPersister
	postHandshake     func(context.Context, *session.Session)
	bandwidthResolver listener.BandwidthResolver
	connGuard         listener.ConnGuardInstaller
	onlineCap         listener.OnlineCapAdmit
	meshResolver      listener.OwnerResolver

	// getCertificate is the cert-svc-backed HTTPS cert source (platform). nil
	// leaves run() on its self-signed wildcard dev/standalone fallback.
	getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)

	// acmeChallengeResolver answers ACME http-01 probes on the visitor HTTP
	// listener (user self-service custom-domain certs). nil in community / no
	// cert-svc, leaving such requests to normal host routing.
	acmeChallengeResolver func(token string) (keyAuth string, ok bool)

	// relayReporter re-sends a merged edge/relay node's OWN relay usage as a
	// self-<label> region (edge/derp merge). nil in community, or when the
	// node has no single-org identity / no relay label — runRelay then relays
	// without reporting.
	relayReporter *relayUsageReporter

	runners []namedRunner
	closers []io.Closer
}

// closeAll closes every collected closer in reverse (LIFO) order, mirroring the
// defer-stack the wiring used to have inline in run().
func closeAll(closers []io.Closer) {
	for i := len(closers) - 1; i >= 0; i-- {
		if c := closers[i]; c != nil {
			_ = c.Close()
		}
	}
}
