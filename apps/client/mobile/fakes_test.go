package mobile

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/calabi/calabi/apps/client/internal/creds"
	"github.com/calabi/calabi/apps/client/internal/hostnet"
	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
	meshpb "github.com/calabi/calabi/pkg/mesh-proto/meshpb"
)

// fakeBFF is the control plane's public API, as much of it as the core uses.
// A refresh token is good for one exchange, like identity-svc's.
type fakeBFF struct {
	mu         sync.Mutex
	access     string // the one access token currently accepted
	refresh    string // the one refresh token currently accepted
	n          int
	enrollment string // GET /v1/mesh/enrollment body
	logouts    []string
	lastLogin  map[string]any

	// Bodies for the GETs the usage and replace screens read; "" = 404.
	me, nodes, current, meshUsage, daily string
	// deleteStatus answers DELETE /v1/mesh/nodes/{id}; 0 = 204.
	deleteStatus int
	deleted      []string          // paths of the DELETEs received
	queries      map[string]string // raw query of the last GET, by path
}

func (f *fakeBFF) issue() (string, string) {
	f.n++
	f.access, f.refresh = fmt.Sprintf("jwt-%d", f.n), fmt.Sprintf("rt-%d", f.n)
	return f.access, f.refresh
}

// expire makes the current access token stop working, as 15 minutes would.
func (f *fakeBFF) expire() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.access = "expired-" + f.access
}

func (f *fakeBFF) currentAccess() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.access
}

func (f *fakeBFF) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	authed := f.access != "" && r.Header.Get("Authorization") == "Bearer "+f.access
	body, _ := io.ReadAll(r.Body)
	reply := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	switch r.Method + " " + r.URL.Path {
	case "POST /v1/auth/login":
		var in map[string]any
		_ = json.Unmarshal(body, &in)
		f.lastLogin = in
		if in["password"] != "hunter2" {
			reply(http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
			return
		}
		access, refresh := f.issue()
		reply(http.StatusOK, map[string]any{"access_token": access, "refresh_token": refresh,
			"user_id": 42, "email": in["identifier"], "active_org_id": 7})
	case "POST /v1/auth/refresh":
		var in struct {
			RefreshToken string `json:"refresh_token"`
		}
		_ = json.Unmarshal(body, &in)
		if in.RefreshToken == "" || in.RefreshToken != f.refresh {
			reply(http.StatusUnauthorized, map[string]string{"error": "session not found"})
			return
		}
		access, refresh := f.issue()
		reply(http.StatusOK, map[string]string{"access_token": access, "refresh_token": refresh})
	case "POST /v1/auth/logout":
		f.logouts = append(f.logouts, r.Header.Get("Authorization"))
		reply(http.StatusOK, map[string]string{})
	case "GET /v1/account/me":
		if !authed {
			reply(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		if f.me != "" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, f.me)
			return
		}
		reply(http.StatusOK, map[string]any{"id": 42, "email": "ada@example.com"})
	case "GET /v1/mesh/nodes", "GET /v1/usage/current", "GET /v1/mesh/usage", "GET /v1/usage/daily":
		if !authed {
			reply(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		if f.queries == nil {
			f.queries = map[string]string{}
		}
		f.queries[r.URL.Path] = r.URL.RawQuery
		b := map[string]string{"/v1/mesh/nodes": f.nodes, "/v1/usage/current": f.current,
			"/v1/mesh/usage": f.meshUsage, "/v1/usage/daily": f.daily}[r.URL.Path]
		if b == "" {
			reply(http.StatusServiceUnavailable, map[string]string{"error": "upstream not configured"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, b)
	case "GET /v1/mesh/enrollment":
		if !authed {
			reply(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, f.enrollment)
	default:
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/mesh/nodes/") {
			if !authed {
				reply(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
			f.deleted = append(f.deleted, r.URL.Path)
			if f.deleteStatus != 0 {
				reply(f.deleteStatus, map[string]string{"error": "refused by the fake"})
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/tunnels") {
			if !authed {
				reply(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
			// Echo what arrived, so a test sees the upstream request the core made.
			reply(http.StatusOK, map[string]string{"path": r.URL.Path, "query": r.URL.RawQuery})
			return
		}
		reply(http.StatusNotFound, map[string]string{"error": "no such route: " + r.URL.Path})
	}
}

// newTestCore starts a fake control plane and a core pointed at it, and undoes
// the process-wide hooks New installs when the test ends.
func newTestCore(t *testing.T, bff *fakeBFF, p *fakePlatform) *Core {
	t.Helper()
	srv := httptest.NewServer(bff)
	t.Cleanup(srv.Close)
	return newTestCoreAt(t, srv.URL, p)
}

// newTestCoreCountingConns is newTestCore whose fake control plane counts the
// TCP connections the core opens to it.
func newTestCoreCountingConns(t *testing.T, bff *fakeBFF, p *fakePlatform) (*Core, *atomic.Int32) {
	t.Helper()
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(bff)
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return newTestCoreAt(t, srv.URL, p), &conns
}

func newTestCoreAt(t *testing.T, bffURL string, p *fakePlatform) *Core {
	t.Helper()
	cfg, _ := json.Marshal(map[string]any{
		"state_dir": t.TempDir(), "bff_url": bffURL, "device_name": "Pixel 8 Pro", "coord_plaintext": true,
	})
	c, err := New(string(cfg), p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c.Disconnect()
		hostnet.SetSocketHook(nil)
		hostnet.SetInterfaceLister(nil)
		creds.SetDataDir("")
	})
	return c
}

func call(t *testing.T, c *Core, method, path, body string) (int, map[string]any) {
	t.Helper()
	var b []byte
	if body != "" {
		b = []byte(body)
	}
	resp := c.Call(method, path, b)
	out := map[string]any{}
	if len(resp.Body) > 0 && !strings.HasPrefix(path, "/v1/logs") {
		if err := json.Unmarshal(resp.Body, &out); err != nil {
			t.Fatalf("%s %s: body is not JSON: %v\n%s", method, path, err, resp.Body)
		}
	}
	return int(resp.Status), out
}

func signIn(t *testing.T, c *Core) {
	t.Helper()
	if code, body := call(t, c, "POST", "/v1/auth/login", `{"email":"ada@example.com","password":"hunter2"}`); code != http.StatusOK {
		t.Fatalf("login = %d %v", code, body)
	}
}

// fakeCoord is a coordinator that registers one node and pushes it one netmap.
type fakeCoord struct {
	meshpb.UnimplementedCoordinatorServer
	netmap *meshpb.NetMap

	mu sync.Mutex
	// failStreams makes that many netmap streams fail at once, as a coordinator
	// connection dropped by the network does.
	failStreams   int
	registrations int
	pending       map[string]meshproto.RegisterChallenge
	ephs          map[string][meshproto.KeyLen]byte
	seq           int
	lastReg       *meshpb.RegisterNodeRequest
}

func startFakeCoord(t *testing.T, nm *meshpb.NetMap) (*fakeCoord, string) {
	t.Helper()
	f := &fakeCoord{netmap: nm, pending: map[string]meshproto.RegisterChallenge{}, ephs: map[string][meshproto.KeyLen]byte{}}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	meshpb.RegisterCoordinatorServer(gs, f)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	return f, lis.Addr().String()
}

func (f *fakeCoord) GetRegisterChallenge(context.Context, *meshpb.GetRegisterChallengeRequest) (*meshpb.GetRegisterChallengeResponse, error) {
	ch, eph, err := meshproto.NewRegisterChallenge()
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	id := fmt.Sprintf("ch-%d", f.seq)
	f.pending[id], f.ephs[id] = ch, eph
	return &meshpb.GetRegisterChallengeResponse{ChallengeId: id, Challenge: ch.Encode()}, nil
}

func (f *fakeCoord) RegisterNode(_ context.Context, req *meshpb.RegisterNodeRequest) (*meshpb.RegisterNodeResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ch, ok := f.pending[req.GetChallengeId()]
	eph := f.ephs[req.GetChallengeId()]
	delete(f.pending, req.GetChallengeId())
	key, err := meshproto.ParseNodeKey(req.GetNodeKey())
	if !ok || err != nil || meshproto.OpenRegisterProof(ch, eph, key, req.GetRegisterProof()) != nil {
		return nil, status.Error(codes.Unauthenticated, "fake: registration proof rejected")
	}
	f.lastReg = req
	f.registrations++
	f.netmap.Self.NodeKey = req.GetNodeKey()
	return &meshpb.RegisterNodeResponse{NodeId: f.netmap.Self.NodeId, OverlayAddr: f.netmap.Self.OverlayAddr,
		ProtocolVersion: meshproto.ProtocolVersion, SessionToken: "session-1"}, nil
}

func (f *fakeCoord) PullNetMap(_ *meshpb.PullNetMapRequest, stream meshpb.Coordinator_PullNetMapServer) error {
	f.mu.Lock()
	nm := f.netmap
	fail := f.failStreams > 0
	if fail {
		f.failStreams--
	}
	f.mu.Unlock()
	if fail {
		return status.Error(codes.Unavailable, "fake: connection lost")
	}
	if err := stream.Send(nm); err != nil {
		return err
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

func (f *fakeCoord) ReportEndpoints(context.Context, *meshpb.ReportEndpointsRequest) (*meshpb.ReportEndpointsResponse, error) {
	return &meshpb.ReportEndpointsResponse{}, nil
}

func (f *fakeCoord) registered() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.registrations
}

func (f *fakeCoord) registration() *meshpb.RegisterNodeRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastReg
}
