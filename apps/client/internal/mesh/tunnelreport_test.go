package mesh

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	meshpb "github.com/calabi/calabi/pkg/mesh-proto/meshpb"
)

// The meter reports what each tunnel added since the last ACCEPTED report: a
// failed one delays bytes instead of losing them, and a new run of counters
// (the tunnel registered again) counts from zero instead of going negative.
func TestTunnelMeterDeltas(t *testing.T) {
	var states []TunnelState
	m := NewTunnelMeter(func() []TunnelState { return states })
	photos := func(instance string, in, out int64) TunnelState {
		return TunnelState{Name: "photos", Type: "http", Status: "online", Instance: instance, BytesIn: in, BytesOut: out}
	}
	step := func(ack bool, want ...int64) {
		t.Helper()
		reports, readings := m.pending()
		var got []int64
		for _, r := range reports {
			got = append(got, r.BytesIn, r.BytesOut)
		}
		if len(got) != len(want) {
			t.Fatalf("reports %+v, want bytes %v", reports, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("reports %+v, want bytes %v", reports, want)
			}
		}
		if ack {
			m.ack(readings)
		}
	}

	states = []TunnelState{photos("a", 100, 10)}
	step(true, 100, 10) // everything so far is new
	states = []TunnelState{photos("a", 150, 30)}
	step(false, 50, 20) // not accepted...
	states = []TunnelState{photos("a", 170, 30)}
	step(true, 70, 20) // ...so the next report carries it too
	states = []TunnelState{photos("b", 5, 1)}
	step(true, 5, 1) // registered again: a new run from zero
	states = []TunnelState{photos("b", 2, 0), {Name: "photos", Type: "tcp", Instance: "b"}}
	step(true, 2, 0) // went backwards: counted from zero; a repeated name is dropped
	states = []TunnelState{photos("c", 50, 10)}
	step(true, 50, 10) // registered again and already past the old reading: still all new
}

type tunnelCoord struct {
	*fakeCoord
	mu     sync.Mutex
	got    []*meshpb.ReportTunnelsRequest
	answer []error // answered in order, then OK
	sent   chan struct{}
}

func (f *tunnelCoord) ReportTunnels(_ context.Context, req *meshpb.ReportTunnelsRequest) (*meshpb.ReportTunnelsResponse, error) {
	f.mu.Lock()
	var err error
	if len(f.answer) > 0 {
		err, f.answer = f.answer[0], f.answer[1:]
	}
	if err == nil {
		f.got = append(f.got, req)
	}
	f.mu.Unlock()
	select {
	case f.sent <- struct{}{}:
	default:
	}
	return &meshpb.ReportTunnelsResponse{}, err
}

func (f *tunnelCoord) accepted() []*meshpb.ReportTunnelsRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*meshpb.ReportTunnelsRequest(nil), f.got...)
}

func dialServer(t *testing.T, srv meshpb.CoordinatorServer) *CoordClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	meshpb.RegisterCoordinatorServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(); gs.Stop(); _ = lis.Close() })
	return NewCoordClient(conn)
}

func runTunnelSession(t *testing.T, f *tunnelCoord, m *TunnelMeter, every time.Duration) context.CancelFunc {
	t.Helper()
	f.fakeCoord = &fakeCoord{
		reg:     &meshpb.RegisterNodeResponse{NodeId: 1, OverlayAddr: "100.64.0.1", SessionToken: "sess"},
		netmaps: []*meshpb.NetMap{{Self: &meshpb.Peer{NodeId: 1, NodeKey: keyB64(1), OverlayAddr: "100.64.0.1"}}},
	}
	ctrl := &Controller{
		Coord:    dialServer(t, f),
		Datapath: &recordingDatapath{ch: make(chan WGConfig, 8)},
		Params:   RegisterParams{AuthKey: "k", NodeKey: testKey(1).Public(), NodePrivate: testKey(1), Name: "n"},
		Tunnels:  m,
		Timing:   &Timing{TunnelReport: every},
		Logger:   slog.Default(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = ctrl.Run(ctx) }()
	t.Cleanup(cancel)
	return cancel
}

func waitReports(t *testing.T, f *tunnelCoord, n int) []*meshpb.ReportTunnelsRequest {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		if got := f.accepted(); len(got) >= n {
			return got
		}
		select {
		case <-f.sent:
		case <-time.After(20 * time.Millisecond):
		case <-deadline:
			t.Fatalf("got %d accepted reports, want %d", len(f.accepted()), n)
		}
	}
}

// A session reports at once, and again as soon as the list changes, well before
// the interval; a failed report's bytes go out with the next one.
func TestTunnelReportLoop(t *testing.T) {
	old, oldRetry := tunnelChangeCheck, tunnelReportRetry
	tunnelChangeCheck, tunnelReportRetry = 20*time.Millisecond, 40*time.Millisecond
	defer func() { tunnelChangeCheck, tunnelReportRetry = old, oldRetry }()

	var mu sync.Mutex
	states := []TunnelState{{Name: "photos", Type: "http", Status: "pending", Instance: "a", BytesIn: 10}}
	m := NewTunnelMeter(func() []TunnelState {
		mu.Lock()
		defer mu.Unlock()
		return append([]TunnelState(nil), states...)
	})
	f := &tunnelCoord{sent: make(chan struct{}, 8), answer: []error{status.Error(codes.Unavailable, "down")}}
	runTunnelSession(t, f, m, time.Hour)

	got := waitReports(t, f, 1)
	if r := got[0].GetTunnels(); len(r) != 1 || r[0].GetBytesIn() != 10 || got[0].GetSessionToken() != "sess" {
		t.Fatalf("first accepted report %v, want photos with the 10 bytes of the one that failed", got[0])
	}
	mu.Lock()
	states = []TunnelState{{Name: "photos", Type: "http", PublicAddr: "photos.example.com", Status: "online", Instance: "a", BytesIn: 25}}
	mu.Unlock()
	got = waitReports(t, f, 2)
	if r := got[1].GetTunnels(); r[0].GetStatus() != "online" || r[0].GetBytesIn() != 15 {
		t.Fatalf("after the change %v, want online and 15 more bytes", got[1])
	}
	time.Sleep(100 * time.Millisecond)
	if n := len(f.accepted()); n != 2 {
		t.Fatalf("%d reports with nothing changed and an hour's interval, want 2", n)
	}
}

// A daemon reports for its whole life, whatever session it has; a coordinator
// that is away is tried again after a pause, not at every look for a change.
func TestTunnelReportRetriesAfterAPause(t *testing.T) {
	old, oldRetry := tunnelChangeCheck, tunnelReportRetry
	tunnelChangeCheck, tunnelReportRetry = 5*time.Millisecond, 100*time.Millisecond
	defer func() { tunnelChangeCheck, tunnelReportRetry = old, oldRetry }()

	m := NewTunnelMeter(func() []TunnelState { return []TunnelState{{Name: "ssh", Type: "tcp", Status: "online"}} })
	var mu sync.Mutex
	tries := 0
	ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
	defer cancel()
	m.Report(ctx, time.Hour, func(context.Context, []TunnelReport) error {
		mu.Lock()
		defer mu.Unlock()
		tries++
		return status.Error(codes.Unavailable, "away")
	}, nil)
	mu.Lock()
	defer mu.Unlock()
	if tries < 2 || tries > 5 {
		t.Fatalf("%d tries in 350ms with a 100ms pause after each failure, want 2 to 5 (not one per 5ms look)", tries)
	}
}

// A coordinator that keeps no tunnels (the platform) is asked once per session.
func TestTunnelReportLoopStopsWhereTunnelsAreNotKept(t *testing.T) {
	old := tunnelChangeCheck
	tunnelChangeCheck = 10 * time.Millisecond
	defer func() { tunnelChangeCheck = old }()

	m := NewTunnelMeter(func() []TunnelState { return nil })
	f := &tunnelCoord{sent: make(chan struct{}, 8), answer: []error{
		status.Error(codes.PermissionDenied, "platform"), status.Error(codes.PermissionDenied, "platform"),
	}}
	runTunnelSession(t, f, m, 10*time.Millisecond)
	select {
	case <-f.sent:
	case <-time.After(3 * time.Second):
		t.Fatal("no report was attempted")
	}
	time.Sleep(150 * time.Millisecond)
	f.mu.Lock()
	left := len(f.answer)
	f.mu.Unlock()
	if left != 1 {
		t.Fatalf("asked %d times, want once", 2-left)
	}
}
