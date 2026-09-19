package rpc

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

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
	meshpb "github.com/calabi/calabi/pkg/mesh-proto/meshpb"
)

// fakeTunnelUsage is the smallest core.TunnelUsageStore that works.
type fakeTunnelUsage struct {
	mu   sync.Mutex
	rows []core.TunnelUsage
}

func (f *fakeTunnelUsage) AddTunnelUsage(_ context.Context, rows []core.TunnelUsage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rows = append(f.rows, rows...)
	return nil
}

func (f *fakeTunnelUsage) TunnelBytesByHour(_ context.Context, t core.MeshnetID, from, to time.Time) (map[time.Time]int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[time.Time]int64{}
	for _, r := range f.rows {
		if r.Meshnet == t && !r.Hour.Before(from) && r.Hour.Before(to) {
			out[r.Hour] += r.BytesIn + r.BytesOut
		}
	}
	return out, nil
}

func (f *fakeTunnelUsage) TunnelBytesSince(_ context.Context, t core.MeshnetID, since time.Time) (map[core.TunnelKey]int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[core.TunnelKey]int64{}
	for _, r := range f.rows {
		if r.Meshnet == t && !r.Hour.Before(since.Truncate(time.Hour)) {
			out[core.TunnelKey{NodeID: r.NodeID, Name: r.Name}] += r.BytesIn + r.BytesOut
		}
	}
	return out, nil
}

func (f *fakeTunnelUsage) PurgeTunnelUsageBefore(context.Context, time.Time) (int, error) {
	return 0, nil
}

type shRig struct {
	c     meshpb.CoordinatorClient
	srv   *Server
	coord *core.Coordinator
}

// startSelfHostedServer runs a self-hosted coordinator keeping tunnels; usage
// nil makes it one without a database.
func startSelfHostedServer(t *testing.T, usage core.TunnelUsageStore) shRig {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	coord := &core.Coordinator{
		Nodes:       core.NewMemNodeStore(),
		Policy:      core.AllowAllPolicy{},
		IPAM:        core.NewMemIPAM(),
		DERP:        core.StaticDERP{Map: core.DERPMap{Regions: []core.DERPRegion{{Code: "lax"}}}},
		AuthKeys:    core.NewMemAuthKeyStore(),
		Tunnels:     core.NewMemTunnelStore(),
		TunnelUsage: usage,
		Presence:    core.NewPresence(),
	}
	auth := core.StaticAuth{Keys: map[string]core.Identity{"file-key": {Meshnet: 1}, "other-org": {Meshnet: 2}}}
	srv := New(coord, auth, core.NewNotifier(), slog.Default())
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
	return shRig{c: meshpb.NewCoordinatorClient(conn), srv: srv, coord: coord}
}

// openView proves n's key for a read-only token.
func openView(ctx context.Context, c meshpb.CoordinatorClient, n testNode) (*meshpb.OpenViewSessionResponse, error) {
	chr, err := c.GetRegisterChallenge(ctx, &meshpb.GetRegisterChallengeRequest{NodeId: n.id, NodeKey: n.key.String()})
	if err != nil {
		return nil, err
	}
	ch, err := meshproto.ParseRegisterChallenge(chr.GetChallenge())
	if err != nil {
		return nil, err
	}
	return c.OpenViewSession(ctx, &meshpb.OpenViewSessionRequest{
		NodeId: n.id, NodeKey: n.key.String(), ChallengeId: chr.GetChallengeId(), Proof: meshproto.SealRegisterProof(ch, n.key, n.priv),
	})
}

// A daemon's report replaces its list: a tunnel it still reports keeps its id,
// one it dropped goes, and its traffic adds up. Every device of the meshnet —
// and only of that meshnet — sees them, under the device that serves them.
func TestTunnelsReportedAndListed(t *testing.T) {
	usage := &fakeTunnelUsage{}
	r := startSelfHostedServer(t, usage)
	ctx := context.Background()
	laptop := enroll(t, r.c, "file-key", "laptop")
	phone := enroll(t, r.c, "file-key", "phone")
	stranger := enroll(t, r.c, "other-org", "stranger")

	report := func(tunnels ...*meshpb.TunnelReport) {
		t.Helper()
		if _, err := r.c.ReportTunnels(ctx, &meshpb.ReportTunnelsRequest{SessionToken: laptop.token, Tunnels: tunnels}); err != nil {
			t.Fatalf("report: %v", err)
		}
	}
	list := func(token string) []*meshpb.TunnelInfo {
		t.Helper()
		resp, err := r.c.ListTunnels(ctx, &meshpb.ListTunnelsRequest{SessionToken: token})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		return resp.GetTunnels()
	}

	report(
		&meshpb.TunnelReport{Name: "photos", Type: "http", PublicAddr: "photos.example.com", LocalAddr: "127.0.0.1:8080", Status: "online", BytesIn: 100, BytesOut: 900},
		&meshpb.TunnelReport{Name: "ssh", Type: "tcp", PublicAddr: "edge.example.com:2222", LocalAddr: "127.0.0.1:22", Status: "online"},
	)
	first := list(phone.token)
	if len(first) != 2 || first[0].GetName() != "photos" || first[0].GetNodeName() != "laptop" || first[0].GetTraffic_30D() != 1000 {
		t.Fatalf("after the first report: %v", first)
	}
	report(&meshpb.TunnelReport{Name: "photos", Type: "http", PublicAddr: "photos.example.com", Status: "online", BytesIn: 50})
	second := list(phone.token)
	if len(second) != 1 || second[0].GetId() != first[0].GetId() || second[0].GetTraffic_30D() != 1050 {
		t.Fatalf("after the second report: %v (first id %d)", second, first[0].GetId())
	}
	if other := list(stranger.token); len(other) != 0 {
		t.Fatalf("another meshnet sees %v", other)
	}
}

// A view token reads without ending the live session, and writes nothing but
// the device's own tunnel report — a device with its mesh switched off still
// serves tunnels.
func TestViewSessionReadsWithoutReplacingTheLiveSession(t *testing.T) {
	r := startSelfHostedServer(t, &fakeTunnelUsage{})
	ctx := context.Background()
	phone := enroll(t, r.c, "file-key", "phone")

	view, err := openView(ctx, r.c, phone)
	if err != nil {
		t.Fatalf("open view: %v", err)
	}
	for name, call := range map[string]func(string) error{
		"ListNodes": func(tok string) error {
			_, err := r.c.ListNodes(ctx, &meshpb.ListNodesRequest{SessionToken: tok})
			return err
		},
		"ListTunnels": func(tok string) error {
			_, err := r.c.ListTunnels(ctx, &meshpb.ListTunnelsRequest{SessionToken: tok})
			return err
		},
		"GetUsage": func(tok string) error {
			_, err := r.c.GetUsage(ctx, &meshpb.GetUsageRequest{SessionToken: tok})
			return err
		},
	} {
		if err := call(view.GetViewToken()); err != nil {
			t.Errorf("%s with the view token: %v", name, err)
		}
		if err := call(phone.token); err != nil {
			t.Errorf("%s with the live token after a view was opened: %v", name, err)
		}
	}
	if _, err := r.c.ReportConnections(ctx, &meshpb.ReportConnectionsRequest{SessionToken: view.GetViewToken()}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("reporting connections with a view token: err = %v, want Unauthenticated", err)
	}
	if _, err := r.c.ReportTunnels(ctx, &meshpb.ReportTunnelsRequest{SessionToken: view.GetViewToken(),
		Tunnels: []*meshpb.TunnelReport{{Name: "nas", Type: "http", Status: "online"}}}); err != nil {
		t.Fatalf("reporting its own tunnels with a view token: %v", err)
	}
	listed, err := r.c.ListTunnels(ctx, &meshpb.ListTunnelsRequest{SessionToken: view.GetViewToken()})
	if err != nil || len(listed.GetTunnels()) != 1 || listed.GetTunnels()[0].GetNodeName() != "phone" {
		t.Fatalf("the tunnel reported over the view session: %v %v", listed, err)
	}
	// Not on the mesh (no map stream), and serving: its report says it is up.
	if !listed.GetTunnels()[0].GetNodeOnline() {
		t.Fatal("a device reporting its tunnels with its mesh off is listed as offline")
	}

	// It expires.
	r.srv.sessions.now = func() time.Time { return time.Now().Add(viewSessionTTL + time.Second) }
	if _, err := r.c.ListNodes(ctx, &meshpb.ListNodesRequest{SessionToken: view.GetViewToken()}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("an expired view token: err = %v, want Unauthenticated", err)
	}
	r.srv.sessions.now = time.Now

	// A device that signed out, or was disabled, reads nothing with one.
	view, err = openView(ctx, r.c, phone)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.SignOut(ctx, &meshpb.SignOutRequest{SessionToken: phone.token}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.ListNodes(ctx, &meshpb.ListNodesRequest{SessionToken: view.GetViewToken()}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("after signing out: err = %v, want FailedPrecondition", err)
	}
	laptop := enroll(t, r.c, "file-key", "laptop")
	view, err = openView(ctx, r.c, laptop)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.coord.Nodes.SetDisabled(ctx, laptop.id, true); err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.ListNodes(ctx, &meshpb.ListNodesRequest{SessionToken: view.GetViewToken()}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("after being disabled: err = %v, want PermissionDenied", err)
	}
}

// The proof is what opens a view: another device's key cannot.
func TestViewSessionNeedsTheNodeKey(t *testing.T) {
	r := startSelfHostedServer(t, nil)
	ctx := context.Background()
	phone := enroll(t, r.c, "file-key", "phone")
	_, otherPriv := newKeyPair(t)
	impostor := phone
	impostor.priv = otherPriv
	if _, err := openView(ctx, r.c, impostor); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("a proof by another key: err = %v, want Unauthenticated", err)
	}
}

// Without a database there is no traffic history: usage says so, rather than 0.
func TestUsageWithoutADatabaseIsUnavailable(t *testing.T) {
	r := startSelfHostedServer(t, nil)
	ctx := context.Background()
	phone := enroll(t, r.c, "file-key", "phone")
	enroll(t, r.c, "file-key", "laptop")
	u, err := r.c.GetUsage(ctx, &meshpb.GetUsageRequest{SessionToken: phone.token, TimeZone: "Asia/Tokyo"})
	if err != nil {
		t.Fatal(err)
	}
	if u.GetUnavailable() != "no_database" || u.GetMonth() != nil || len(u.GetDays()) != 0 {
		t.Fatalf("usage = %v, want unavailable with no figures", u)
	}
	if u.GetDevicesUsed() != 2 || u.GetDevicesLimit() != -1 {
		t.Fatalf("devices used %d limit %d, want 2 and -1", u.GetDevicesUsed(), u.GetDevicesLimit())
	}
}

// With usage kept, the days are the viewer's.
func TestUsageDaysAreTheViewers(t *testing.T) {
	usage := &fakeTunnelUsage{}
	r := startSelfHostedServer(t, usage)
	ctx := context.Background()
	laptop := enroll(t, r.c, "file-key", "laptop")
	if _, err := r.c.ReportTunnels(ctx, &meshpb.ReportTunnelsRequest{SessionToken: laptop.token, Tunnels: []*meshpb.TunnelReport{
		{Name: "photos", Type: "http", Status: "online", BytesIn: 40, BytesOut: 60},
	}}); err != nil {
		t.Fatal(err)
	}
	u, err := r.c.GetUsage(ctx, &meshpb.GetUsageRequest{SessionToken: laptop.token, TimeZone: "Pacific/Auckland", Days: 3})
	if err != nil {
		t.Fatal(err)
	}
	loc, _ := time.LoadLocation("Pacific/Auckland")
	now := time.Now().In(loc)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	days := u.GetDays()
	if len(days) != 3 || days[2].GetStartUnix() != today.Unix() || days[2].GetBytes() != 100 {
		t.Fatalf("days = %v, want 3 ending today %v with 100 bytes", days, today)
	}
	if u.GetMonth().GetTunnelBytes() != 100 || !u.GetRelayNotRecorded() {
		t.Fatalf("month = %v relay_not_recorded %v", u.GetMonth(), u.GetRelayNotRecorded())
	}
}

// Every one of these belongs to the platform's own API on a coordinator with
// an identity service.
func TestSelfHostedCallsAreRefusedOnThePlatform(t *testing.T) {
	platform := startReauthServer(t)
	ctx := context.Background()
	n, _ := enrollWithCaps(t, platform.c, "alice-token", "laptop")
	calls := map[string]error{}
	_, calls["ReportTunnels"] = platform.c.ReportTunnels(ctx, &meshpb.ReportTunnelsRequest{SessionToken: n.token})
	_, calls["ListTunnels"] = platform.c.ListTunnels(ctx, &meshpb.ListTunnelsRequest{SessionToken: n.token})
	_, calls["GetUsage"] = platform.c.GetUsage(ctx, &meshpb.GetUsageRequest{SessionToken: n.token})
	_, calls["OpenViewSession"] = openView(ctx, platform.c, n)
	_, calls["GetEdgeAccess"] = platform.c.GetEdgeAccess(ctx, &meshpb.GetEdgeAccessRequest{SessionToken: n.token})
	for name, err := range calls {
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s on the platform: err = %v, want PermissionDenied", name, err)
		}
	}
}
