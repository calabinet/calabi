package observability

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Options configures a Provider.
type Options struct {
	// Service is the canonical short name -- "calabi-edge", "identity-svc"...
	// It labels build_info and prefixes the admin server's component logs.
	Service string
	// Version is the semver / build tag of the running binary.
	Version string
	// AdminAddr is the address the /healthz + /readyz + /metrics server
	// binds to. Default ":9101". Per-service deployments should override
	// to avoid port collisions; in dev k8s a sidecar pattern works too.
	AdminAddr string
	// IsReady is an optional dependency-level readiness check called by
	// /readyz. nil = the in-process ready flag is sufficient.
	IsReady func() (bool, string)
}

// Provider bundles the Prometheus registry and the admin HTTP server.
//
// Lifecycle:
//
//	prov := observability.New(observability.Options{Service: "identity-svc", Version: "0.1.0"})
//	// register your domain collectors:
//	prov.Registry().MustRegister(myCounter)
//	go func() { _ = prov.Run(ctx) }()
//	prov.SetReady(true)
//	... // serve traffic
//	prov.SetReady(false)
//	cancel()
type Provider struct {
	opts   Options
	logger *slog.Logger

	registry *prometheus.Registry
	ready    atomic.Bool
}

// New constructs a Provider with the standard runtime collectors + a
// build_info gauge already registered.
func New(logger *slog.Logger, opts Options) *Provider {
	if opts.Service == "" {
		opts.Service = "unknown"
	}
	if opts.Version == "" {
		opts.Version = "(devel)"
	}
	if opts.AdminAddr == "" {
		opts.AdminAddr = ":9101"
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "calabi_build_info",
		Help: "Constant 1 with service + version labels for dashboard joins.",
	}, []string{"service", "version", "go_version", "vcs_revision"})
	reg.MustRegister(buildInfo)
	gov, rev := readBuildInfo()
	buildInfo.WithLabelValues(opts.Service, opts.Version, gov, rev).Set(1)

	return &Provider{
		opts:     opts,
		logger:   logger.With("component", "observability"),
		registry: reg,
	}
}

// Registry exposes the Prometheus registry for domain-specific collectors.
func (p *Provider) Registry() *prometheus.Registry { return p.registry }

// SetReady toggles process readiness. Call SetReady(true) once all
// dependencies are connected; call SetReady(false) before graceful
// shutdown so a load balancer drains traffic.
func (p *Provider) SetReady(ready bool) { p.ready.Store(ready) }

// Run binds and serves the admin endpoints until ctx is cancelled.
// Returns nil on graceful shutdown.
func (p *Provider) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", p.handleHealthz)
	mux.HandleFunc("/readyz", p.handleReadyz)
	mux.Handle("/metrics", promhttp.HandlerFor(p.registry, promhttp.HandlerOpts{
		Registry:          p.registry,
		EnableOpenMetrics: true,
	}))
	mux.HandleFunc("/", p.handleIndex)

	ln, err := net.Listen("tcp", p.opts.AdminAddr)
	if err != nil {
		return fmt.Errorf("observability listen %s: %w", p.opts.AdminAddr, err)
	}
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	p.logger.Info("admin listener up",
		"service", p.opts.Service,
		"addr", p.opts.AdminAddr,
	)

	srvErr := make(chan error, 1)
	go func() {
		err := srv.Serve(ln)
		if err != nil && err != http.ErrServerClosed {
			srvErr <- err
			return
		}
		srvErr <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return nil
	case err := <-srvErr:
		return err
	}
}

func (p *Provider) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (p *Provider) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if !p.ready.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("starting\n"))
		return
	}
	if p.opts.IsReady != nil {
		ok, reason := p.opts.IsReady()
		if !ok {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintf(w, "not ready: %s\n", reason)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (p *Provider) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "calabi %s admin (%s)\n\n", p.opts.Service, p.opts.Version)
	fmt.Fprintln(w, "  GET /healthz  liveness")
	fmt.Fprintln(w, "  GET /readyz   readiness")
	fmt.Fprintln(w, "  GET /metrics  prometheus exposition")
}

func readBuildInfo() (goVer, revision string) {
	goVer = "unknown"
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	goVer = bi.GoVersion
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" {
			revision = s.Value
		}
	}
	return
}
