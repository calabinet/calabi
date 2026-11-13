package mesh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type rdpReporterRPC struct {
	meshpb.CoordinatorClient
	calls   chan *meshpb.ReportRdpCertificateRequest
	results chan error
}

func (r *rdpReporterRPC) ReportRdpCertificate(ctx context.Context, req *meshpb.ReportRdpCertificateRequest, _ ...grpc.CallOption) (*meshpb.ReportRdpCertificateResponse, error) {
	select {
	case r.calls <- req:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case err := <-r.results:
		return &meshpb.ReportRdpCertificateResponse{}, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestRDPCertificateReporterRegistrationRecovery(t *testing.T) {
	pin := bytes.Repeat([]byte{1}, 32)
	rotatedPin := bytes.Repeat([]byte{2}, 32)
	type step struct {
		token     string
		pin       []byte
		readErr   error
		reportErr error
		// Replace the session while the previous publication is in flight.
		duringReport string
	}
	for _, tc := range []struct {
		name  string
		steps []step
	}{
		{"unchanged_certificate_new_registration", []step{
			{token: "first", pin: pin},
			{token: "second", pin: pin},
		}},
		{"replacement_during_successful_publication", []step{
			{token: "first", pin: pin, duringReport: "second"},
			{token: "second", pin: pin},
		}},
		{"replacement_during_rejected_publication", []step{
			{token: "first", pin: pin, duringReport: "second", reportErr: status.Error(codes.Unauthenticated, "session ended")},
			{token: "second", pin: pin},
		}},
		{"retry_failed_republication", []step{
			{token: "first", pin: pin},
			{token: "second", pin: pin, reportErr: status.Error(codes.Unavailable, "offline")},
			{token: "second", pin: pin},
		}},
		{"withdraw_restore_and_rotate", []step{
			{token: "first", pin: pin},
			{token: "first", readErr: errors.New("listener unavailable")},
			{token: "second", readErr: errors.New("listener unavailable")},
			{token: "second", pin: pin},
			{token: "second", pin: rotatedPin},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			rpc := &rdpReporterRPC{calls: make(chan *meshpb.ReportRdpCertificateRequest), results: make(chan error)}
			coord := &CoordClient{rpc: rpc}
			setToken := func(token string) {
				coord.sessMu.Lock()
				coord.session = token
				coord.sessMu.Unlock()
			}
			reads := make(chan step)
			refresh := make(chan struct{}, 1)
			done := make(chan struct{})
			go func() {
				defer close(done)
				runRDPCertificateReporter(ctx, coord, slog.New(slog.NewTextHandler(io.Discard, nil)), refresh, func(ctx context.Context) ([]byte, error) {
					select {
					case s := <-reads:
						return s.pin, s.readErr
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				})
			}()
			t.Cleanup(func() {
				cancel()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("certificate reporter did not stop")
				}
			})
			for i, s := range tc.steps {
				setToken(s.token)
				if i > 0 {
					refresh <- struct{}{}
				}
				select {
				case reads <- s:
				case <-ctx.Done():
					t.Fatalf("step %d: reporter did not wake after registration", i)
				}
				select {
				case req := <-rpc.calls:
					if req.SessionToken != s.token || !bytes.Equal(req.Sha256, s.pin) {
						t.Fatalf("step %d: publication used the wrong session or certificate", i)
					}
				case <-ctx.Done():
					t.Fatalf("step %d: missing certificate publication", i)
				}
				if s.duringReport != "" {
					setToken(s.duringReport)
				}
				select {
				case rpc.results <- s.reportErr:
				case <-ctx.Done():
					t.Fatalf("step %d: publication did not complete", i)
				}
			}
		})
	}
}
