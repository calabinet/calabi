// Package metrics is the standardization helper for
// Prometheus exposition across all Calabi services.
//
// One Recorder per process is registered into the observability Provider's
// registry. Every gRPC / HTTP handler reports through the Recorder using
// the same four label dimensions so Grafana panels can `sum by (svc,
// handler, code)` without per-service glue:
//
//	calabi_handler_requests_total{svc, handler, code, org_id, plan}
//	calabi_handler_duration_seconds{svc, handler, code, org_id, plan}
//
// `org_id` + `plan` are business labels filled by handlers that have
// them; gRPC interceptors fill `""` when the call's context doesn't
// carry the principal yet. Empty values are cheap in Prometheus and keep
// the label cardinality bounded (no `unknown_*` magic strings).
//
// Wiring:
//
//	prov := observability.New(logger, observability.Options{Service: "quota-svc", ...})
//	rec  := metrics.NewRecorder(prov.Registry(), "quota-svc")
//	grpcSrv := grpc.NewServer(grpc.UnaryInterceptor(metrics.UnaryServerInterceptor(rec)))
//	// or, for HTTP:
//	mux := http.NewServeMux()
//	wrapped := metrics.HTTPMiddleware(rec)(mux)
//
// pkg/svcboot.Run already does this hookup for every grpc/http handler
// it owns; service code calls Recorder.Observe directly only for
// background workers that aren't on a request hot path (e.g.,
// metering-svc's NATS consumer loop).
package metrics

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Standard label keys. Exported so handlers can keep them in sync with
// the Grafana dashboards without re-hardcoding strings.
const (
	LabelSvc     = "svc"
	LabelHandler = "handler"
	LabelCode    = "code"
	LabelOrgID   = "org_id"
	LabelPlan    = "plan"
)

// labelOrder is the canonical ordering the collectors are registered with;
// passing labels in a different order to WithLabelValues silently bins
// into the wrong cells.
var labelOrder = []string{LabelSvc, LabelHandler, LabelCode, LabelOrgID, LabelPlan}

// LabelOrder returns a copy of the canonical label key order. Useful for
// callers building label maps programmatically.
func LabelOrder() []string {
	out := make([]string, len(labelOrder))
	copy(out, labelOrder)
	return out
}

// Recorder bundles the standard counter + histogram for one service.
// Safe for concurrent use.
type Recorder struct {
	svc       string
	requests  *prometheus.CounterVec
	durations *prometheus.HistogramVec
}

// NewRecorder registers the standard collectors into reg and returns a
// ready-to-use Recorder for service svc. Panics if reg already has
// collectors with the same name (use a fresh prometheus.Registry per
// process, which observability.New does for you).
func NewRecorder(reg prometheus.Registerer, svc string) *Recorder {
	if svc == "" {
		svc = "unknown"
	}
	requests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "calabi_handler_requests_total",
		Help: "Count of handler invocations per (svc, handler, code, org_id, plan).",
	}, labelOrder)
	durations := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "calabi_handler_duration_seconds",
		Help:    "Wall-clock duration of handler invocations.",
		Buckets: prometheus.DefBuckets,
	}, labelOrder)
	reg.MustRegister(requests, durations)
	return &Recorder{svc: svc, requests: requests, durations: durations}
}

// Observe records one handler invocation. handler is the gRPC method or
// HTTP route ("/v1/usage/current"), code is the gRPC code name
// ("OK", "InvalidArgument", ...) or HTTP status class ("2xx", "5xx").
// orgID/plan may be "" when not known.
//
// Use this directly when you can't wrap with an interceptor (background
// workers, NATS consumers, etc.).
func (r *Recorder) Observe(handler, code, orgID, plan string, dur time.Duration) {
	if r == nil {
		return
	}
	values := []string{r.svc, handler, code, orgID, plan}
	r.requests.WithLabelValues(values...).Inc()
	r.durations.WithLabelValues(values...).Observe(dur.Seconds())
}

// SvcName returns the service name this recorder is anchored to.
func (r *Recorder) SvcName() string { return r.svc }

// UnaryServerInterceptor wires r into every gRPC unary call. Handler
// label is the gRPC method (e.g. "/calabi.v1.control_plane.Quota/CheckAdmit");
// code label is the resulting gRPC status code name. Business labels
// (org_id, plan) default to "" -- if a handler wants to fill them, it
// stuffs values into the call context via ContextWithBusinessLabels and
// the interceptor reads them out on return.
func UnaryServerInterceptor(r *Recorder) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		start := time.Now()
		ctx = withBusinessLabelsHolder(ctx)
		resp, err := handler(ctx, req)
		code := grpcCode(err)
		orgID, plan := businessLabelsFrom(ctx)
		r.Observe(info.FullMethod, code, orgID, plan, time.Since(start))
		return resp, err
	}
}

// HTTPMiddleware wraps an http.Handler so every request reports into r.
// Handler label is the matched route (best-effort: r.URL.Path when no
// pattern info is available); code label is the HTTP status class
// ("2xx", "3xx", "4xx", "5xx") to bound cardinality.
func HTTPMiddleware(r *Recorder) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			start := time.Now()
			rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			ctxHolder := withBusinessLabelsHolder(req.Context())
			next.ServeHTTP(rw, req.WithContext(ctxHolder))
			orgID, plan := businessLabelsFrom(ctxHolder)
			r.Observe(routeOf(req), httpClass(rw.status), orgID, plan, time.Since(start))
		})
	}
}

// SetBusinessLabels lets handlers fill org_id / plan after authenticating
// the caller. The values are picked up by the surrounding interceptor /
// middleware when the call returns.
func SetBusinessLabels(ctx context.Context, orgID int64, plan string) {
	h := businessLabelsHolderFrom(ctx)
	if h == nil {
		return
	}
	if orgID > 0 {
		h.orgID = strconv.FormatInt(orgID, 10)
	}
	if plan != "" {
		h.plan = plan
	}
}

// ---------- internals ----------

type businessLabels struct {
	orgID string
	plan  string
}

type bizCtxKey struct{}

func withBusinessLabelsHolder(ctx context.Context) context.Context {
	if businessLabelsHolderFrom(ctx) != nil {
		return ctx
	}
	return context.WithValue(ctx, bizCtxKey{}, &businessLabels{})
}

func businessLabelsHolderFrom(ctx context.Context) *businessLabels {
	v, _ := ctx.Value(bizCtxKey{}).(*businessLabels)
	return v
}

func businessLabelsFrom(ctx context.Context) (orgID, plan string) {
	h := businessLabelsHolderFrom(ctx)
	if h == nil {
		return "", ""
	}
	return h.orgID, h.plan
}

func grpcCode(err error) string {
	if err == nil {
		return codes.OK.String()
	}
	return status.Code(err).String()
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wrote {
		s.status = code
		s.wrote = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.wrote = true
	return s.ResponseWriter.Write(b)
}

func httpClass(code int) string {
	switch {
	case code >= 500:
		return "5xx"
	case code >= 400:
		return "4xx"
	case code >= 300:
		return "3xx"
	case code >= 200:
		return "2xx"
	default:
		return strconv.Itoa(code)
	}
}

// routeOf returns the matched server pattern when net/http exposes one
// (Go 1.22+), falling back to the raw path. Path-based metrics would
// blow up cardinality with IDs in the URL, so we only use it as a last
// resort. Handlers that want clean labels should register routes with
// http.ServeMux pattern syntax (e.g. "GET /v1/tunnels/{id}") -- the
// returned pattern is then stable.
func routeOf(r *http.Request) string {
	if r.Pattern != "" {
		return r.Pattern
	}
	// Strip query string but keep path; this is best-effort and callers
	// are nudged via doc.go to use Go 1.22 pattern syntax instead.
	p := r.URL.Path
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	return p
}
