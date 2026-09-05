// calabi-coord is the mesh coordinator — the control plane for Calabi's Connect
// (WireGuard mesh) data plane: node registry, IPAM (100.64.0.0/10),
// ACL-filtered netmap, MagicDNS, and the DERP relay map. It is the "brain"
// described in
//
// MESH.1 (this slice) closes the minimal loop: the Coordinator gRPC service
// (RegisterNode / PullNetMap stream / ReportEndpoints) is served over the
// standard svcboot server, backed by the core through the wire.go seam.
// Netmaps are full-mesh (AllowAllPolicy); ACLs, hole punching, and MagicDNS
// land in later slices.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"google.golang.org/grpc"

	"github.com/calabi/calabi/apps/calabi-coord/internal/adminhttp"
	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
	"github.com/calabi/calabi/apps/calabi-coord/internal/rpc"
	meshpb "github.com/calabi/calabi/pkg/mesh-proto/meshpb"
	"github.com/calabi/calabi/pkg/svcboot"
)

// version is stamped at link time with `-X main.version=<v>` (Dockerfile).
// It was `serviceVersion = "0.0.0-mesh.1"` inside this const block, which the
// linker cannot rewrite and which no build flag named - see the long note in
// apps/calabi-edge/cmd/calabi-edge/main.go; coord had the identical bug. svcboot
// logs this at startup and reports it on the admin surface, so until now both
// said "0.0.0-mesh.1" no matter what shipped.
var version = "dev"

const (
	serviceName = "calabi-coord"
	// Provisional dev ports — the next free slots after config-svc (:7010 /
	// :9121) and audit-svc (:7011). Overridable via CALABI_COORD_GRPC_ADDR /
	// CALABI_COORD_ADMIN_ADDR (see env.go).
	defaultGRPC  = ":7012"
	defaultAdmin = ":9122"
)

func main() {
	// Before anything else: let the binary say which build it is. coord ships to
	// people who run it themselves now, and until 2026-09-05 there was no way to
	// ask it - the version was a const the linker could not stamp (see `version`
	// above), so even the startup log lied.
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}

	logger := svcboot.NewLogger()

	// Decide the mesh-admin posture BEFORE anything starts serving: an
	// unauthenticated /admin/* surface is a cross-meshnet takeover, so a missing
	// token aborts the process rather than degrading (see meshadminauth.go).
	meshAdmin, err := resolveMeshAdmin()
	if err != nil {
		logger.Error("calabi-coord refusing to start", "err", err)
		os.Exit(1)
	}
	// Same idea, wider net: in production none of the dev fallbacks may be
	// active (see prodguard.go). Checked before wire() so the process dies
	// before it authenticates anything.
	if err := checkProductionPosture(); err != nil {
		logger.Error("calabi-coord refusing to start", "err", err)
		os.Exit(1)
	}

	// Every setting has now been read, so say once which deprecated names were
	// used — after configuration rather than during it, so a var read twice does
	// not warn twice (see env.go).
	reportLegacyEnv(logger)

	coord, auth, err := wire(logger)
	if err != nil {
		logger.Error("calabi-coord wiring failed", "err", err)
		os.Exit(1)
	}
	logger.Info("calabi-coord core wired")

	notif := core.NewNotifier()
	// Hot-reload the ACL policy file and re-push netmaps on change (no-op unless
	// CALABI_COORD_POLICY_FILE is set). Started here so it has the notifier.
	startPolicyWatcher(logger, notif)
	srv := rpc.New(coord, auth, notif, logger)

	if err := svcboot.Run(svcboot.Options{
		Name:    serviceName,
		Version: version,
		// State the env namespace instead of letting svcboot derive it from Name.
		// Name is what the public export renames (calabi-coord -> calabi-coord), so a
		// derived prefix made the two trees read DIFFERENT variables from the same
		// source while every comment named the same one. See env.go.
		EnvPrefix:        envPrefix,
		LegacyEnvPrefix:  legacyEnvPrefix,
		DefaultGRPCAddr:  defaultGRPC,
		DefaultAdminAddr: defaultAdmin,
		// Coord's gRPC is the one control-plane surface a client dials over the
		// public internet, so it can serve TLS itself (edge-CA server cert) rather
		// than needing a front proxy. Empty/plaintext when unconfigured (dev).
		// The keepalive options are what let a daemon detect a control connection
		// that died without a RST (see keepalive.go — ship this before the client).
		GRPCServerOptions: append(coordServerCreds(logger), coordKeepaliveOptions()...),
		Register: func(s *grpc.Server) error {
			meshpb.RegisterCoordinatorServer(s, srv)
			return nil
		},
		// Node-admin HTTP surface (MESH.8b): list / disable / enable nodes. Served
		// only when CALABI_COORD_MESH_ADMIN_ADDR is set, on a PRIVATE address (the
		// bff-admin gateway is its authenticated front door).
		Extra: withEdgeDERPWatcher(notif, withRelayUsageCollection(coord, logger, meshAdminServer(meshAdmin, coord, notif, logger))),
	}); err != nil {
		os.Exit(1)
	}
}

// withRelayUsageCollection starts the relay usage poller (F2) alongside whatever
// else the Extra hook runs, bound to the same shutdown context. A coordinator
// with no collection configured starts nothing — which is every deployment until
// its relays are given a usage token.
func withRelayUsageCollection(coord *core.Coordinator, logger *slog.Logger, next func(context.Context) error) func(context.Context) error {
	return func(ctx context.Context) error {
		if p := newRelayUsagePoller(coord, loadRelayUsageAddrs(logger), logger); p != nil {
			go p.Run(ctx)
		}
		return next(ctx)
	}
}

// edgeDERPWatcher refreshes the DERP map from the relay directory and re-pushes
// netmaps on change (see derpmap_edges.go). A plain func value, left nil when no
// platform hooks address is configured — a self-hosted coordinator with a static
// map wires nothing here.
var edgeDERPWatcher func(context.Context, *core.Notifier)

// withEdgeDERPWatcher starts the edge-derived DERP refresher (if the platform
// refresher set edgeDERPWatcher) bound to the Extra hook's shutdown context,
// then runs next. No-op when no platform hooks address is configured.
func withEdgeDERPWatcher(notif *core.Notifier, next func(context.Context) error) func(context.Context) error {
	return func(ctx context.Context) error {
		if edgeDERPWatcher != nil {
			go edgeDERPWatcher(ctx, notif)
		}
		return next(ctx)
	}
}

// meshAdminServer returns an svcboot Extra hook that serves the node-admin HTTP
// API on CALABI_COORD_MESH_ADMIN_ADDR. If that env is unset it serves nothing and
// simply blocks until shutdown, so no port is opened by default.
func meshAdminServer(set meshAdminSettings, coord *core.Coordinator, notif *core.Notifier, logger *slog.Logger) func(context.Context) error {
	return func(ctx context.Context) error {
		if set.Addr == "" {
			<-ctx.Done()
			return nil
		}
		var h http.Handler = adminhttp.New(coord, notif, logger)
		if set.Token != "" {
			h = meshAdminAuth(set.Token, h)
		}
		srv := &http.Server{Addr: set.Addr, Handler: h}
		go func() {
			<-ctx.Done()
			_ = srv.Shutdown(context.Background())
		}()
		set.logPosture(logger)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	}
}
