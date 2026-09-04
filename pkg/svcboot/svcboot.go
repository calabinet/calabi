// Package svcboot is the shared bootstrap for Calabi control-plane
// microservices. Every service (identity, tenant, tunnel, quota, config,
// bff-cli) calls svcboot.Run with its name + service-specific gRPC server
// registration callback, and gets back:
//
//   - structured logger (slog text/json by env)
//   - observability admin server (/healthz, /readyz, /metrics)
//   - gRPC server with grpc_health_v1.Health registered
//   - gRPC server reflection (helpful for grpcurl in dev)
//   - SIGINT/SIGTERM-aware graceful shutdown
//
// The intent is that an empty service is one main.go of ~20 lines.
// Domain logic lands in internal/* and is registered via the Register
// callback.
//
// Configuration is intentionally env-only at this stage. swaps
// to viper + config-svc subscriptions.
package svcboot

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	// Embedded IANA tzdata. Required so time.LoadLocation("Asia/Shanghai")
	// resolves on Windows / scratch container images that don't ship
	// /usr/share/zoneinfo. Adds ~500KB per binary; acceptable for our
	// "every timestamp displays in Beijing time" requirement.
	_ "time/tzdata"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	"github.com/calabi/calabi/pkg/observability"
	"github.com/calabi/calabi/pkg/observability/metrics"
)

// TZ is the process-wide display timezone for every Calabi binary
// (both control-plane svcs and the bff-console / dev tools that
// embed svcboot). Defaults to Asia/Shanghai per product requirement;
// override with the CALABI_TZ env var (e.g. UTC, Europe/Berlin) for
// unit tests or non-CN deployments. The init() below also assigns
// this value to time.Local so calls like `t.Format(time.RFC3339)`,
// slog timestamps, and `ent` schema defaults of `time.Now` all emit
// in the same zone without further plumbing.
//
// IMPORTANT: this is a display label. Database storage (Postgres
// timestamptz) is always UTC on the wire; only the rendered string
// changes. ensuredb additionally runs `ALTER DATABASE ... SET
// timezone` so direct psql / pgAdmin sessions see Beijing time too.
var TZ *time.Location

func init() {
	name := strings.TrimSpace(os.Getenv("CALABI_TZ"))
	if name == "" {
		name = "Asia/Shanghai"
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		// Should never happen with time/tzdata imported above, but
		// fall back to a fixed +08:00 offset rather than crash —
		// every binary needs to boot even with a typo'd CALABI_TZ.
		loc = time.FixedZone("CST", 8*3600)
	}
	TZ = loc
	time.Local = loc
}

// Options configures Run.
type Options struct {
	// Name is the service short name -- "identity-svc", "tenant-svc", ...
	Name string

	// EnvPrefix overrides the env-var prefix, which otherwise comes from Name
	// (uppercased, '-' -> '_'). Empty = derive from Name, which is what every
	// in-cluster service wants.
	//
	// It exists because deriving the prefix from the service NAME silently ties
	// configuration to branding. calabi-coord is published as "calabi-coord", and
	// the export rewrites that string -- so the same source produced a binary
	// reading COORD_SVC_GRPC_ADDR here and CALABI_COORD_GRPC_ADDR there, while
	// every doc comment in both said COORD_SVC_*. Naming the prefix explicitly
	// is what stops a rename from being a config change.
	EnvPrefix string

	// LegacyEnvPrefix is a second prefix read when the primary is unset, so an
	// env-var rename does not break a running deployment. Empty = no fallback.
	// A value picked up through it is logged once, by name, at startup.
	LegacyEnvPrefix string
	// Version is the binary version string.
	Version string
	// DefaultGRPCAddr is the address to bind the gRPC server to if the
	// service-specific env var isn't set. Empty = no gRPC server (e.g. bff-cli).
	DefaultGRPCAddr string
	// DefaultAdminAddr is the address for /healthz + /metrics. Should be
	// unique per service in dev to avoid collisions on shared box.
	DefaultAdminAddr string

	// Register is called once the gRPC server is constructed; the callback
	// should register service-specific RPC handlers. Nil = no domain RPCs
	// (only health + reflection are registered).
	Register func(*grpc.Server) error

	// GRPCServerOptions are extra grpc.ServerOptions applied to the gRPC server,
	// in addition to the standard metrics interceptor. A service passes
	// grpc.Creds(...) here to serve TLS on its listener — used by calabi-coord, whose
	// gRPC is the one internal control-plane surface a client dials directly over
	// the public internet. Empty = the default plaintext server (every in-cluster
	// service, whose gRPC never leaves the compose / VPC network).
	GRPCServerOptions []grpc.ServerOption

	// Extra hooks for non-gRPC services (e.g. bff-cli serves HTTP). The
	// callback runs in its own goroutine; returning a non-nil error aborts
	// the process. The callback receives the Options value with the
	// `recorder` field populated -- HTTP svcs that want the standard
	// label set should wrap their mux with metrics.HTTPMiddleware(opts.Recorder()).
	Extra func(context.Context) error

	// recorder is populated by Run before invoking Extra; service code
	// reaches it via Recorder().
	recorder *metrics.Recorder
}

// Recorder returns the metrics recorder owned by this Run invocation.
// Useful for HTTP services that need to wrap their mux in the standard
// {svc, handler, code, org_id, plan} middleware. Returns nil before
// Run() has been entered.
func (o *Options) Recorder() *metrics.Recorder { return o.recorder }

// Run boots a control-plane service. It blocks until the process receives
// SIGINT/SIGTERM, the gRPC server returns an error, or ctx is cancelled.
//
// Env vars (looked up before falling back to Options defaults):
//
//	{NAME}_GRPC_ADDR      e.g. IDENTITY_SVC_GRPC_ADDR=:7001
//	{NAME}_ADMIN_ADDR     e.g. IDENTITY_SVC_ADMIN_ADDR=:9111
//	LOG_LEVEL             debug|info|warn|error  (default info)
//	LOG_FORMAT            text|json              (default text)
//
// {NAME} is Options.Name uppercased with '-' replaced by '_'.
func Run(opts Options) error {
	logger := newLogger()
	logger.Info("starting", "service", opts.Name, "version", opts.Version)

	envPrefix := strings.TrimSpace(opts.EnvPrefix)
	if envPrefix == "" {
		envPrefix = strings.ReplaceAll(strings.ToUpper(opts.Name), "-", "_")
	}
	grpcAddr := envOrLegacy(logger, envPrefix, opts.LegacyEnvPrefix, "_GRPC_ADDR", opts.DefaultGRPCAddr)
	adminAddr := envOrLegacy(logger, envPrefix, opts.LegacyEnvPrefix, "_ADMIN_ADDR", opts.DefaultAdminAddr)

	prov := observability.New(logger, observability.Options{
		Service:   opts.Name,
		Version:   opts.Version,
		AdminAddr: adminAddr,
	})

	// Standardized per-handler metrics with {svc, handler, code, org_id,
	// plan} labels. The interceptor is wired below
	// when the gRPC server is constructed; HTTP svcs can wrap their
	// http.Handler with metrics.HTTPMiddleware(rec). Recorder is keyed
	// to opts.Name so dashboards `sum by (svc)` correctly.
	rec := metrics.NewRecorder(prov.Registry(), opts.Name)
	opts.recorder = rec // exposed via Options for HTTP svcs' Extra hook

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	errCh := make(chan error, 3)

	// 1. Admin (always on).
	go func() {
		if err := prov.Run(ctx); err != nil {
			errCh <- fmt.Errorf("observability: %w", err)
			return
		}
		errCh <- nil
	}()

	// 2. gRPC server (optional).
	var grpcSrv *grpc.Server
	var healthSvc *health.Server
	if grpcAddr != "" {
		serverOpts := append([]grpc.ServerOption{grpc.UnaryInterceptor(metrics.UnaryServerInterceptor(rec))}, opts.GRPCServerOptions...)
		grpcSrv = grpc.NewServer(serverOpts...)
		healthSvc = health.NewServer()
		// Empty string is the conventional "overall service" key.
		healthSvc.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
		healthpb.RegisterHealthServer(grpcSrv, healthSvc)
		reflection.Register(grpcSrv)

		if opts.Register != nil {
			if err := opts.Register(grpcSrv); err != nil {
				return fmt.Errorf("register gRPC: %w", err)
			}
		}

		ln, err := net.Listen("tcp", grpcAddr)
		if err != nil {
			return fatalBindError(logger, opts.Name, "grpc", grpcAddr, err)
		}
		logger.Info("grpc listener up", "addr", grpcAddr)

		go func() {
			if err := grpcSrv.Serve(ln); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				errCh <- fmt.Errorf("grpc: %w", err)
				return
			}
			errCh <- nil
		}()
	}

	// 3. Extra hook (e.g. HTTP server for bff-cli).
	if opts.Extra != nil {
		go func() {
			if err := opts.Extra(ctx); err != nil {
				errCh <- fmt.Errorf("extra: %w", err)
				return
			}
			errCh <- nil
		}()
	}

	// Brief grace window to let Extra's listener call Listen() and either
	// bind cleanly or report failure. Bind errors fire synchronously
	// (EADDRINUSE returns immediately from net.Listen), so anything that
	// shows up in errCh within ~250ms is almost certainly a startup
	// failure rather than the long-running listener exiting. We treat
	// those as fatal: log a loud banner, refuse to flip SetReady, and
	// propagate the error so the process exits non-zero (the previous
	// version returned nil here, so a bff-* binary with an EADDRINUSE
	// would silently exit 0 — kubernetes/systemd thought it succeeded
	// and didn't restart it).
	select {
	case err := <-errCh:
		if err != nil {
			fatalListenerExit(logger, opts.Name, err)
			// Don't bother with graceful shutdown — the listener never
			// came up; whatever did bind (admin / grpc) the OS will
			// reclaim on process exit.
			return err
		}
		// nil from one of the goroutines this early means it exited
		// cleanly (rare — usually ctx-cancellation, but we haven't
		// cancelled yet). Fall through; SetReady will still flip.
	case <-time.After(startupGracePeriod):
		// No errors within the grace window → all listeners are up.
	}

	prov.SetReady(true)
	if healthSvc != nil {
		healthSvc.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	}
	ready.Store(true)

	var runErr error
	select {
	case <-ctx.Done():
		logger.Info("shutdown requested", "service", opts.Name)
	case err := <-errCh:
		if err != nil {
			fatalListenerExit(logger, opts.Name, err)
			runErr = err
		}
	}

	// Graceful shutdown.
	prov.SetReady(false)
	if healthSvc != nil {
		healthSvc.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
	}
	if grpcSrv != nil {
		// GracefulStop with a hard kill backstop.
		stopped := make(chan struct{})
		go func() { grpcSrv.GracefulStop(); close(stopped) }()
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			grpcSrv.Stop()
		}
	}
	return runErr
}

// startupGracePeriod is how long Run waits after spawning Extra before
// flipping SetReady. Bind errors fire synchronously inside net.Listen,
// so 250ms is enough for an EADDRINUSE to surface but short enough not
// to delay a healthy boot meaningfully.
const startupGracePeriod = 250 * time.Millisecond

// fatalBindError logs a multi-line banner for a Listen() failure on a
// known listener (grpc / admin / specific Extra listener that returns
// to the parent goroutine). Returned error is wrapped with file:port
// context so the caller's `return fatalBindError(...)` still propagates.
//
// The banner is intentionally noisy: previous incidents had bff-console
// fail to bind :8002 and the single-line error got buried under normal
// startup chatter from sibling services. ASCII bars + repeated "FATAL"
// make it grep-able and impossible to miss in scrollback.
func fatalBindError(logger *slog.Logger, svc, kind, addr string, err error) error {
	wrapped := fmt.Errorf("%s listen %s: %w", kind, addr, err)
	hint := ""
	if strings.Contains(err.Error(), "address already in use") ||
		strings.Contains(err.Error(), "Only one usage of each socket address") {
		hint = "another process is bound to this port — `lsof -i :<port>` / `netstat -ano | findstr :<port>` will show who"
	}
	banner := strings.Repeat("=", 72)
	logger.Error(banner)
	logger.Error("FATAL: " + svc + " could not bind " + kind + " listener")
	logger.Error("       addr: " + addr)
	logger.Error("       err:  " + err.Error())
	if hint != "" {
		logger.Error("       hint: " + hint)
	}
	logger.Error(banner)
	return wrapped
}

// fatalListenerExit logs the same banner format for a long-running
// listener that exited unexpectedly (i.e. its Serve goroutine returned
// an error). Distinct from fatalBindError because here the error has
// already been wrapped by the goroutine — we just want the loud
// presentation + a non-zero return.
func fatalListenerExit(logger *slog.Logger, svc string, err error) {
	banner := strings.Repeat("=", 72)
	logger.Error(banner)
	logger.Error("FATAL: " + svc + " listener exited")
	logger.Error("       err: " + err.Error())
	logger.Error(banner)
}

// MaybeMigrate centralizes the boot-time schema decision every stateful
// svc shares. It replaces the old hand-rolled two-liner
//
//	if err := st.Migrate(ctx); err != nil { ...; os.Exit(1) }
//	svcboot.ExitIfMigrateOnly()
//
// with a single call that ALSO understands SKIP_MIGRATE.
//
// Behaviour by env (MIGRATE_ONLY wins when both are set — a migration
// job must actually migrate):
//
//	MIGRATE_ONLY=1   run migrate, then os.Exit(0). The dedicated
//	                 migration Job / `make migrate-apply` path.
//	SKIP_MIGRATE=1   skip migrate entirely and return so the process
//	                 keeps booting. Used by runtime pods that reach PG
//	                 through PgBouncer transaction pooling, where ent /
//	                 atlas schema introspection trips "unnamed prepared
//	                 statement does not exist (26000)". Schema is applied
//	                 out-of-band — the migration Job, or db-bootstrap.ps1
//	                 in dev — against a DIRECT (non-pooled) connection.
//	(neither)        run migrate, then keep booting. The legacy direct-PG
//	                 / in-memory-SQLite dev path where re-applying the
//	                 idempotent schema on every boot is harmless.
//
// migrate is a closure (not a method value) so callers that do more than
// one schema step — e.g. metering-svc's Migrate + ApplyViews — can wrap
// the whole sequence and have SKIP_MIGRATE / MIGRATE_ONLY gate all of it.
func MaybeMigrate(migrate func() error) {
	migrateOnly := envTrue("MIGRATE_ONLY")
	if !migrateOnly && envTrue("SKIP_MIGRATE") {
		fmt.Fprintln(os.Stderr, "svcboot: SKIP_MIGRATE set — skipping schema migration (applied out-of-band)")
		return
	}
	if err := migrate(); err != nil {
		fmt.Fprintf(os.Stderr, "migrate: %v\n", err)
		os.Exit(1)
	}
	if migrateOnly {
		fmt.Fprintln(os.Stderr, "svcboot: MIGRATE_ONLY=1, schema applied, exiting")
		os.Exit(0)
	}
}

// envTrue reports whether an env var is set to a truthy value ("1" or
// "true", case-insensitive). Shared by MaybeMigrate + ExitIfMigrateOnly.
func envTrue(key string) bool {
	v := strings.TrimSpace(os.Getenv(key))
	return v == "1" || strings.EqualFold(v, "true")
}

// ExitIfMigrateOnly exits with status 0 when MIGRATE_ONLY=1, after the
// caller has already run its store.Migrate().
//
// Deprecated: prefer MaybeMigrate, which folds the migrate call, this
// exit check, and the SKIP_MIGRATE escape hatch into one. Retained for
// any out-of-tree caller; all in-tree svcs now use MaybeMigrate.
func ExitIfMigrateOnly() {
	if envTrue("MIGRATE_ONLY") {
		fmt.Fprintln(os.Stderr, "svcboot: MIGRATE_ONLY=1, schema applied, exiting")
		os.Exit(0)
	}
}

// Ready returns whether the most recent Run() call has reached steady
// state. Useful for non-trivial tests.
func Ready() bool { return ready.Load() }

var ready atomic.Bool

// SetupLogger builds the same logger svcboot.Run uses internally
// (stdout, TextHandler by default, JSONHandler if LOG_FORMAT=json,
// level from LOG_LEVEL) AND installs it as the slog package default
// via slog.SetDefault. Call this as the first thing in main(), before
// any code that emits log lines — otherwise pre-Run logs go through
// Go's stock slog.Default() which writes to STDERR and lands in a
// different file (the run.ps1 stack splits stdout / stderr).
//
// Returns the logger so call-sites can pass it into their own helpers
// without a second slog.Default() lookup.
//
// Idempotent: calling twice just rebuilds + reinstalls.
func SetupLogger() *slog.Logger {
	l := newLogger()
	slog.SetDefault(l)
	return l
}

// NewLogger is SetupLogger without the slog.SetDefault side effect.
// Useful for tests or sub-loggers that don't want to clobber a
// caller-supplied default.
func NewLogger() *slog.Logger {
	return newLogger()
}

func newLogger() *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if strings.EqualFold(os.Getenv("LOG_FORMAT"), "json") {
		h = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		h = slog.NewTextHandler(os.Stdout, opts)
	}
	return slog.New(h)
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// envOrLegacy reads prefix+suffix, then legacy+suffix, then falls back to def.
//
// Using the old name still WORKS but says so, loudly and by name. A silent
// compatibility shim is how a deprecated variable survives for years: nobody
// finds out they are relying on it until the day it is deleted.
func envOrLegacy(logger *slog.Logger, prefix, legacy, suffix, def string) string {
	if v := strings.TrimSpace(os.Getenv(prefix + suffix)); v != "" {
		return v
	}
	if legacy != "" {
		if v := strings.TrimSpace(os.Getenv(legacy + suffix)); v != "" {
			logger.Warn("using a DEPRECATED env var; rename it",
				"deprecated", legacy+suffix, "use", prefix+suffix)
			return v
		}
	}
	return def
}
