package mesh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type recoveryCoord struct {
	*fakeCoord
	requests       []*meshpb.RegisterNodeRequest
	pulls          int
	streamCode     codes.Code
	refuse         codes.Code
	changeIdentity bool
	abort          chan struct{}
	editStarted    chan struct{}
	editRelease    chan struct{}
	badDelta       bool
	stallFirst     bool
	holdFirst      bool
}

func (f *recoveryCoord) RegisterNode(ctx context.Context, req *meshpb.RegisterNodeRequest) (*meshpb.RegisterNodeResponse, error) {
	resp, err := f.fakeCoord.RegisterNode(ctx, req) // verify the actual new challenge proof
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, proto.Clone(req).(*meshpb.RegisterNodeRequest))
	if len(f.requests) > 1 && f.refuse != codes.OK {
		return nil, status.Error(f.refuse, "reauthorization refused")
	}
	r := proto.Clone(resp).(*meshpb.RegisterNodeResponse)
	r.SessionToken = fmt.Sprintf("fresh-%d", len(f.requests))
	if len(f.requests) > 1 {
		r.Capabilities = nil
	}
	if len(f.requests) > 1 && f.changeIdentity {
		r.NodeId++
	}
	return r, nil
}

func (f *recoveryCoord) PullNetMap(req *meshpb.PullNetMapRequest, stream meshpb.Coordinator_PullNetMapServer) error {
	f.mu.Lock()
	f.pulls++
	n := f.pulls
	current := fmt.Sprintf("fresh-%d", len(f.requests))
	f.mu.Unlock()
	if req.SessionToken != current {
		return status.Error(codes.Unauthenticated, "old token")
	}
	if n == 1 && f.stallFirst {
		<-stream.Context().Done()
		return stream.Context().Err()
	}
	m := &meshpb.NetMap{Sequence: 1, Self: &meshpb.Peer{NodeId: 1, NodeKey: keyB64(1), OverlayAddr: "100.64.0.1"}, FilterEnabled: true, FileTransferSupported: true}
	if n == 1 {
		m.Peers = []*meshpb.Peer{{NodeId: 2, NodeKey: keyB64(2), OverlayAddr: "100.64.0.2"}}
	}
	if n > 1 && f.badDelta {
		m.Sequence = 2
		m.Delta = true
		m.BaseSequence = 1
	}
	if err := stream.Send(m); err != nil {
		return err
	}
	if n == 1 {
		if f.holdFirst {
			<-stream.Context().Done()
			return stream.Context().Err()
		}
		if f.abort != nil {
			select {
			case <-f.abort:
			case <-stream.Context().Done():
				return stream.Context().Err()
			}
		}
		return status.Error(f.streamCode, "stream ended")
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

func TestWatchFirstMapDeadlineAndQuietSubscription(t *testing.T) {
	for _, stall := range []bool{true, false} {
		t.Run(fmt.Sprint(stall), func(t *testing.T) {
			f := &recoveryCoord{fakeCoord: &fakeCoord{reg: &meshpb.RegisterNodeResponse{NodeId: 1, OverlayAddr: "100.64.0.1"}}, stallFirst: stall, holdFirst: !stall}
			c := dialFake(t, f)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			p := RegisterParams{AuthKey: "key", NodeKey: testKey(1).Public(), NodePrivate: testKey(1)}
			if _, err := c.Register(ctx, p); err != nil {
				t.Fatal(err)
			}
			var expired atomic.Int32
			mapped := make(chan struct{}, 1)
			done := make(chan error, 1)
			go func() {
				done <- c.watchReauthenticated(ctx, 1, watchRecovery{initialTimeout: 50 * time.Millisecond, onTimeout: func() { expired.Add(1) }, refresh: func(ctx context.Context) error { _, err := c.Register(ctx, p); return err }}, func(NetMap) { mapped <- struct{}{} }, nil)
			}()
			select {
			case <-mapped:
			case <-ctx.Done():
				t.Fatal("first map did not recover")
			}
			// Once a first frame arrived, a quiet stream must stay open beyond its initial deadline.
			time.Sleep(150 * time.Millisecond)
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("watch leaked")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			want := 1
			if stall {
				want = 2
			}
			if len(f.requests) != want || f.pulls != want || expired.Load() != int32(want-1) {
				t.Fatalf("registrations=%d streams=%d timeouts=%d", len(f.requests), f.pulls, expired.Load())
			}
		})
	}
}

func (f *recoveryCoord) UpdateNodeDeclarations(ctx context.Context, _ *meshpb.UpdateNodeDeclarationsRequest) (*meshpb.UpdateNodeDeclarationsResponse, error) {
	close(f.editStarted)
	select {
	case <-f.editRelease:
		return &meshpb.UpdateNodeDeclarationsResponse{}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type recoveryDatapath struct {
	recordingDatapath
	attached atomic.Int32
	detached atomic.Int32
}

func (d *recoveryDatapath) attachDirect(*magicSock, pathFinder) { d.attached.Add(1) }
func (d *recoveryDatapath) detachDirect()                       { d.detached.Add(1) }

func TestControllerReauthenticatesSupersededWatch(t *testing.T) {
	for _, tc := range []struct {
		name           string
		stream, refuse codes.Code
		changed        bool
	}{
		{"recover", codes.Aborted, codes.OK, false},
		{"revoked", codes.Aborted, codes.PermissionDenied, false},
		{"identity_down", codes.Aborted, codes.Unavailable, false},
		{"identity_changed", codes.Aborted, codes.OK, true},
		{"bad_delta", codes.Aborted, codes.OK, false},
		{"network_failure", codes.Unavailable, codes.OK, false},
		{"denied_stream", codes.PermissionDenied, codes.OK, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &recoveryCoord{fakeCoord: &fakeCoord{reg: &meshpb.RegisterNodeResponse{NodeId: 1, OverlayAddr: "100.64.0.1", Capabilities: []string{string(meshproto.CapFileTransfer)}}}, streamCode: tc.stream, refuse: tc.refuse, changeIdentity: tc.changed}
			f.badDelta = tc.name == "bad_delta"
			dp := &recoveryDatapath{recordingDatapath: recordingDatapath{ch: make(chan WGConfig, 4)}}
			ctrl := &Controller{Coord: dialFake(t, f), Datapath: dp, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Params: RegisterParams{AuthKey: "key", NodeKey: testKey(1).Public(), NodePrivate: testKey(1), Name: "test"}}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- ctrl.Run(ctx) }()
			if tc.name == "recover" {
				for i := 0; i < 2; i++ {
					select {
					case cfg := <-dp.ch:
						if i == 1 && (len(cfg.Peers) != 0 || !cfg.FilterEnabled) {
							t.Fatal("old map survived recovery")
						}
					case <-ctx.Done():
						t.Fatal("recovery did not complete")
					}
				}
				if ctrl.fileTransferNegotiated.Load() {
					t.Fatal("lost registration capability stayed enabled")
				}
				cancel()
			}
			select {
			case err := <-done:
				if tc.stream == codes.Aborted && tc.name != "recover" && tc.name != "bad_delta" && !errors.Is(err, ErrRegister) {
					t.Fatalf("recovery auth error: %v", err)
				}
			case <-ctx.Done():
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("controller failed to stop")
				}
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			want := 1
			if tc.stream == codes.Aborted {
				want = 2
			}
			if len(f.requests) != want {
				t.Fatalf("registrations=%d want=%d", len(f.requests), want)
			}
			if want == 2 {
				a, b := f.requests[0], f.requests[1]
				if a.ChallengeId == b.ChallengeId || len(b.RegisterProof) == 0 || a.DiscoKey == "" || a.DiscoKey != b.DiscoKey {
					t.Fatal("proof not refreshed or live transport key changed")
				}
			}
			if tc.name != "recover" && tc.name != "bad_delta" && f.pulls != 1 {
				t.Fatal("subscribed after failure")
			}
			if tc.name == "bad_delta" && (f.pulls != 2 || len(dp.ch) != 1) {
				t.Fatal("old delta baseline reused")
			}
			if dp.attached.Load() != 1 || dp.detached.Load() != 1 {
				t.Fatal("discovery transport restarted or leaked")
			}
			if !ctrl.Registered() {
				t.Fatal("registration history lost after session ended")
			}
			if ctrl.FileTransferReady() {
				t.Fatal("file transfer ready after session ended")
			}
		})
	}
}

func TestNewTransportStillRotatesDiscoveryKey(t *testing.T) {
	f := &recoveryCoord{fakeCoord: &fakeCoord{reg: &meshpb.RegisterNodeResponse{NodeId: 1, OverlayAddr: "100.64.0.1"}}, streamCode: codes.Unavailable}
	dp := &recoveryDatapath{recordingDatapath: recordingDatapath{ch: make(chan WGConfig, 4)}}
	c := &Controller{Coord: dialFake(t, f), Datapath: dp, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Params: RegisterParams{AuthKey: "key", NodeKey: testKey(1).Public(), NodePrivate: testKey(1)}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Run(ctx); status.Code(err) != codes.Unavailable {
		t.Fatalf("network failure: %v", err)
	}
	<-dp.ch
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	select {
	case <-dp.ch:
	case <-ctx.Done():
		t.Fatal("new transport did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("session leaked")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) != 2 || f.requests[0].DiscoKey == f.requests[1].DiscoKey {
		t.Fatal("transport restart reused discovery key")
	}
	if dp.attached.Load() != 2 || dp.detached.Load() != 2 {
		t.Fatal("transport lifecycle mismatch")
	}
}

func TestRegistrationGateCancellation(t *testing.T) {
	c := &Controller{}
	unlock, err := c.lockRegistration(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if release, err := c.lockRegistration(ctx); !errors.Is(err, context.DeadlineExceeded) || release != nil {
		t.Fatalf("blocked registration ignored cancellation: %v", err)
	}
}

func TestRecoveryKeepsConcurrentDeclarationEdit(t *testing.T) {
	f := &recoveryCoord{fakeCoord: &fakeCoord{reg: &meshpb.RegisterNodeResponse{NodeId: 1, OverlayAddr: "100.64.0.1", Capabilities: []string{string(meshproto.CapFileTransfer)}}}, streamCode: codes.Aborted, abort: make(chan struct{}), editStarted: make(chan struct{}), editRelease: make(chan struct{})}
	dp := &recordingDatapath{ch: make(chan WGConfig, 4)}
	c := &Controller{Coord: dialFake(t, f), Datapath: dp, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Params: RegisterParams{AuthKey: "key", NodeKey: testKey(1).Public(), NodePrivate: testKey(1)}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	select {
	case <-dp.ch:
	case <-ctx.Done():
		t.Fatal("initial map missing")
	}
	edited := make(chan error, 1)
	go func() {
		edited <- c.UpdateDeclarations(ctx, []DeclaredService{{Name: "new-service", Proto: "tcp", Port: 8080}}, "new-fingerprint")
	}()
	select {
	case <-f.editStarted:
	case <-ctx.Done():
		t.Fatal("edit not started")
	}
	close(f.abort)
	for c.fileTransferNegotiated.Load() {
		select {
		case <-ctx.Done():
			t.Fatal("recovery did not wait for declaration edit")
		case <-time.After(time.Millisecond):
		}
	}
	close(f.editRelease)
	if err := <-edited; err != nil {
		t.Fatal(err)
	}
	select {
	case <-dp.ch:
	case <-ctx.Done():
		t.Fatal("recovery map missing")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("recovery did not exit")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) != 2 || len(f.requests[1].DeclaredServices) != 1 || f.requests[1].DeclaredServices[0].Name != "new-service" || f.requests[1].DeviceFingerprint != "new-fingerprint" {
		t.Fatal("recovery rolled back declaration edit")
	}
}

func TestWatchRecoveryBackoffCancels(t *testing.T) {
	f := &recoveryCoord{fakeCoord: &fakeCoord{reg: &meshpb.RegisterNodeResponse{NodeId: 1, OverlayAddr: "100.64.0.1"}}, streamCode: codes.Aborted}
	c := dialFake(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p := RegisterParams{AuthKey: "key", NodeKey: testKey(1).Public(), NodePrivate: testKey(1)}
	if _, err := c.Register(ctx, p); err != nil {
		t.Fatal(err)
	}
	interrupted := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- c.watchReauthenticated(ctx, 1, watchRecovery{interrupted: func() { close(interrupted) }, refresh: func(ctx context.Context) error {
			_, err := c.Register(ctx, p)
			return err
		}}, func(NetMap) {}, nil)
	}()
	select {
	case <-interrupted:
	case <-ctx.Done():
		t.Fatal("no reauthentication")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("backoff ignored cancellation")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pulls != 1 || len(f.requests) != 1 {
		t.Fatal("subscribed after shutdown")
	}
}

func TestNetworkChangeWakesSubscriptionRecovery(t *testing.T) {
	f := &recoveryCoord{fakeCoord: &fakeCoord{reg: &meshpb.RegisterNodeResponse{NodeId: 1, OverlayAddr: "100.64.0.1", Capabilities: []string{string(meshproto.CapFileTransfer)}}}, streamCode: codes.Aborted}
	dp := &recordingDatapath{ch: make(chan WGConfig, 4)}
	c := &Controller{Coord: dialFake(t, f), Datapath: dp, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Params: RegisterParams{AuthKey: "key", NodeKey: testKey(1).Public(), NodePrivate: testKey(1)}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	select {
	case <-dp.ch:
	case <-ctx.Done():
		t.Fatal("no initial map")
	}
	for c.fileTransferNegotiated.Load() {
		select {
		case <-ctx.Done():
			t.Fatal("not recovering")
		case <-time.After(time.Millisecond):
		}
	}
	c.NetworkChanged()
	select {
	case <-dp.ch:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("network change waited for retry timer")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("controller leaked")
	}
}
