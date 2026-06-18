package metrics

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// We test the *shape* of the recorder (label keys, code derivation,
// status-class bucketing, defensive no-panic) rather than absolute
// counter values -- the underlying prometheus library is well-trusted,
// what sets is the label convention and the wiring.

func TestRecorder_LabelOrder(t *testing.T) {
	got := LabelOrder()
	want := []string{"svc", "handler", "code", "org_id", "plan"}
	if len(got) != len(want) {
		t.Fatalf("len mismatch: %d vs %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("position %d: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestRecorder_Observe_DoesNotPanic(t *testing.T) {
	reg := prometheus.NewRegistry()
	r := NewRecorder(reg, "test-svc")
	r.Observe("/test/Handler", "OK", "42", "free", 10*time.Millisecond)
	r.Observe("/test/Handler", "OK", "", "", 5*time.Millisecond)
	r.Observe("/test/Handler", "InvalidArgument", "42", "free", 2*time.Millisecond)
	if r.SvcName() != "test-svc" {
		t.Errorf("svc name lost: %q", r.SvcName())
	}
}

func TestRecorder_NilSvc_DefaultsToUnknown(t *testing.T) {
	reg := prometheus.NewRegistry()
	r := NewRecorder(reg, "")
	if r.SvcName() != "unknown" {
		t.Errorf("empty svc must default to 'unknown', got %q", r.SvcName())
	}
}

func TestUnaryInterceptor_RecordsOK(t *testing.T) {
	reg := prometheus.NewRegistry()
	r := NewRecorder(reg, "test-svc")
	interceptor := UnaryServerInterceptor(r)

	called := false
	handler := func(ctx context.Context, _ interface{}) (interface{}, error) {
		called = true
		SetBusinessLabels(ctx, 42, "pro")
		return "ok", nil
	}
	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{
		FullMethod: "/calabi.v1.TestSvc/Hi",
	}, handler)
	if err != nil {
		t.Fatalf("interceptor returned err: %v", err)
	}
	if !called {
		t.Fatal("handler not invoked")
	}
}

func TestUnaryInterceptor_RecordsError(t *testing.T) {
	reg := prometheus.NewRegistry()
	r := NewRecorder(reg, "test-svc")
	interceptor := UnaryServerInterceptor(r)

	handler := func(_ context.Context, _ interface{}) (interface{}, error) {
		return nil, status.Error(codes.NotFound, "missing")
	}
	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{
		FullMethod: "/calabi.v1.TestSvc/Get",
	}, handler)
	if status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound, got %v", err)
	}
}

func TestHTTPMiddleware_StatusClass(t *testing.T) {
	reg := prometheus.NewRegistry()
	r := NewRecorder(reg, "test-svc")
	mw := HTTPMiddleware(r)

	cases := []struct {
		name string
		code int
		want string
	}{
		{"200 -> 2xx", http.StatusOK, "2xx"},
		{"301 -> 3xx", http.StatusMovedPermanently, "3xx"},
		{"404 -> 4xx", http.StatusNotFound, "4xx"},
		{"500 -> 5xx", http.StatusInternalServerError, "5xx"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(c.code)
			}))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/healthz", nil))
			if rec.Code != c.code {
				t.Errorf("status passthrough broken: got %d", rec.Code)
			}
			if got := httpClass(rec.Code); got != c.want {
				t.Errorf("httpClass(%d) = %q, want %q", rec.Code, got, c.want)
			}
		})
	}
}

func TestGRPCCode_NilIsOK(t *testing.T) {
	if got := grpcCode(nil); got != "OK" {
		t.Errorf("nil err should map to OK, got %q", got)
	}
	if got := grpcCode(status.Error(codes.PermissionDenied, "no")); got != "PermissionDenied" {
		t.Errorf("got %q", got)
	}
	if got := grpcCode(errors.New("naked")); !strings.Contains(got, "Unknown") {
		t.Errorf("naked err should map to Unknown, got %q", got)
	}
}

func TestSetBusinessLabels_OutsideInterceptor_DoesNotPanic(t *testing.T) {
	// Calling SetBusinessLabels in a context that never went through the
	// interceptor / middleware must be a no-op, not a panic. This is the
	// "handler-can-be-called-from-anywhere" defensive guarantee.
	SetBusinessLabels(context.Background(), 1, "free")
}
