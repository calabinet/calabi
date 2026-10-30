package mesh

import (
	"context"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Only bounded classifications are exported. Local synthetic-fixture logs keep
// the first transport error for diagnosis, never request bodies or credentials.
type fleetRPCDiagnostics struct {
	mu     sync.Mutex
	counts map[string]int
}

type fleetDiagnosticStream struct {
	grpc.ClientStream
	diagnostics *fleetRPCDiagnostics
	method      string
	once        sync.Once
}

func (s *fleetDiagnosticStream) RecvMsg(v any) error {
	err := s.ClientStream.RecvMsg(v)
	if err != nil {
		s.once.Do(func() {
			kind := status.Code(err).String()
			if status.Convert(err).Message() == "netmap changed during send; reconnect for current snapshot" {
				kind += "/map_changed_during_send"
			}
			s.diagnostics.mu.Lock()
			defer s.diagnostics.mu.Unlock()
			if s.diagnostics.counts == nil {
				s.diagnostics.counts = map[string]int{}
			}
			s.diagnostics.counts[s.method+"/stream_end/"+kind]++
		})
	}
	return err
}
func (d *fleetRPCDiagnostics) streamInterceptor() grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, next grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		s, err := next(ctx, desc, cc, method, opts...)
		if err != nil {
			return nil, err
		}
		return &fleetDiagnosticStream{ClientStream: s, diagnostics: d, method: method}, nil
	}
}

func (d *fleetRPCDiagnostics) interceptor(t *testing.T) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoke grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		err := invoke(ctx, method, req, reply, cc, opts...)
		kind := status.Code(err).String()
		if status.Code(err) == codes.Unavailable {
			msg := status.Convert(err).Message()
			switch {
			case strings.Contains(msg, "cannot confirm this device"):
				kind += "/identity_dependency"
			case strings.Contains(msg, "actively refused") || strings.Contains(msg, "connection refused"):
				kind += "/transport_connection_refused"
			case strings.Contains(msg, "connection error"):
				kind += "/transport_connection"
			case strings.Contains(msg, "EOF"):
				kind += "/transport_eof"
			default:
				kind += "/other"
			}
		}
		key := method + "/" + kind
		d.mu.Lock()
		if d.counts == nil {
			d.counts = make(map[string]int)
		}
		d.counts[key]++
		first := d.counts[key] == 1
		d.mu.Unlock()
		if first && err != nil {
			t.Logf("fixture RPC transport diagnostic %s: %v", key, err)
		}
		return err
	}
}

func (d *fleetRPCDiagnostics) snapshot() map[string]int {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[string]int, len(d.counts))
	for k, v := range d.counts {
		out[k] = v
	}
	return out
}

type fleetErrorStream struct {
	grpc.ClientStream
	err error
}

func (s *fleetErrorStream) RecvMsg(any) error { return s.err }

func TestFleetStreamDiagnosticCountsOnceWithoutErrorBody(t *testing.T) {
	for _, tc := range []struct{ message, suffix string }{
		{"netmap changed during send; reconnect for current snapshot", "/map_changed_during_send"},
		{"sensitive-device-token", ""},
	} {
		d := &fleetRPCDiagnostics{}
		s := &fleetDiagnosticStream{ClientStream: &fleetErrorStream{err: status.Error(codes.Aborted, tc.message)}, diagnostics: d, method: "PullNetMap"}
		for i := 0; i < 3; i++ {
			if s.RecvMsg(nil) == nil {
				t.Fatal("error swallowed")
			}
		}
		got := d.snapshot()
		if len(got) != 1 || got["PullNetMap/stream_end/Aborted"+tc.suffix] != 1 {
			t.Fatalf("unexpected diagnostic: %v", got)
		}
	}
}
