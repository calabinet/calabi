package mobile

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
	meshpb "github.com/calabi/calabi/pkg/mesh-proto/meshpb"
)

// shCoord is a self-hosted coordinator stand-in serving TLS on a self-signed
// certificate: it admits keys it knows, takes enrolled nodes back by proof
// alone when it offers node_reauth, lists its nodes and records sign-outs.
type shCoord struct {
	meshpb.UnimplementedCoordinatorServer
	addr string
	pin  string // the certificate it started with
	cert atomic.Pointer[tls.Certificate]
	stop func()

	mu        sync.Mutex
	keys      map[string]bool
	offer     bool
	deleted   bool // forget the node: re-registration by proof alone is NotFound
	pending   map[string]meshproto.RegisterChallenge
	ephs      map[string][meshproto.KeyLen]byte
	seq       int
	regs      []string // "key:<key>" or "reauth:<node id>"
	signedOut int
	nodeKey   string // the registered node's key, for the netmap's Self
	// View sessions: how many were opened, and a token it has forgotten (as
	// after a restart) so the next read with it is refused.
	views       int
	forgotView  string
	unavailable string // GetUsage says so: no database
	usageTZ     string // the time zone the last GetUsage asked for
}

// session checks a token the lists accept: the live session's or a view's.
func (f *shCoord) session(tok string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if tok == "" || tok == f.forgotView || (tok != "sh-session" && !strings.HasPrefix(tok, "sh-view-")) {
		return status.Error(codes.Unauthenticated, "no session")
	}
	return nil
}

func (f *shCoord) OpenViewSession(_ context.Context, req *meshpb.OpenViewSessionRequest) (*meshpb.OpenViewSessionResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ch, ok := f.pending[req.GetChallengeId()]
	eph := f.ephs[req.GetChallengeId()]
	delete(f.pending, req.GetChallengeId())
	key, err := meshproto.ParseNodeKey(req.GetNodeKey())
	if !ok || err != nil || meshproto.OpenRegisterProof(ch, eph, key, req.GetProof()) != nil {
		return nil, status.Error(codes.Unauthenticated, "proof rejected")
	}
	f.views++
	return &meshpb.OpenViewSessionResponse{ViewToken: fmt.Sprintf("sh-view-%d", f.views), ExpiresUnix: time.Now().Add(10 * time.Minute).Unix()}, nil
}

func (f *shCoord) ListTunnels(_ context.Context, req *meshpb.ListTunnelsRequest) (*meshpb.ListTunnelsResponse, error) {
	if err := f.session(req.GetSessionToken()); err != nil {
		return nil, err
	}
	seen := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC).Unix()
	return &meshpb.ListTunnelsResponse{Tunnels: []*meshpb.TunnelInfo{
		{Id: 3, NodeId: 22, NodeName: "nas", NodeOnline: true, Name: "photos", Type: "http", PublicAddr: "photos.example.com",
			LocalAddr: "127.0.0.1:8080", Status: "online", Traffic_30D: 5000, FirstSeenUnix: seen},
		{Id: 4, NodeId: 23, NodeName: "old-laptop", NodeOnline: false, Name: "ssh", Type: "tcp", PublicAddr: "edge.example.com:2222",
			LocalAddr: "127.0.0.1:22", Status: "online", FirstSeenUnix: seen},
	}}, nil
}

func (f *shCoord) GetUsage(_ context.Context, req *meshpb.GetUsageRequest) (*meshpb.GetUsageResponse, error) {
	if err := f.session(req.GetSessionToken()); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.usageTZ = req.GetTimeZone()
	out := &meshpb.GetUsageResponse{DevicesUsed: 3, DevicesDisabled: 1, DevicesLimit: -1, Unavailable: f.unavailable}
	if f.unavailable == "" {
		out.Month = &meshpb.UsageMonth{FromUnix: 1, ToUnix: 2, TunnelBytes: 700, RelayBytes: 300}
		out.Days = []*meshpb.UsageDay{{StartUnix: 86400, Bytes: 10}, {StartUnix: 2 * 86400, Bytes: 990}}
	}
	return out, nil
}

func startSHCoord(t *testing.T, offer bool, keys ...string) *shCoord {
	t.Helper()
	cert, pin := selfSignedCert(t)
	f := &shCoord{keys: map[string]bool{}, offer: offer, pin: pin,
		pending: map[string]meshproto.RegisterChallenge{}, ephs: map[string][meshproto.KeyLen]byte{}}
	f.cert.Store(cert)
	for _, k := range keys {
		f.keys[k] = true
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.addr = lis.Addr().String()
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return f.cert.Load(), nil },
	})))
	meshpb.RegisterCoordinatorServer(gs, f)
	go func() { _ = gs.Serve(lis) }()
	f.stop = gs.Stop
	t.Cleanup(gs.Stop)
	return f
}

func selfSignedCert(t *testing.T) (*tls.Certificate, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "calabi-coord"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, meshproto.CertPin(leaf)
}

// rotateCert makes the server present a new certificate — its administrator
// regenerated it, or someone else answers at its address — and returns its pin.
func (f *shCoord) rotateCert(t *testing.T) string {
	cert, pin := selfSignedCert(t)
	f.cert.Store(cert)
	return pin
}

func (f *shCoord) link(key string) string {
	return "calabi://join?" + url.Values{"v": {"1"}, "s": {f.addr}, "k": {key}, "fp": {f.pin}}.Encode()
}

func (f *shCoord) registrations() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.regs...)
}

func (f *shCoord) GetRegisterChallenge(_ context.Context, req *meshpb.GetRegisterChallengeRequest) (*meshpb.GetRegisterChallengeResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if req.GetAuthKey() == "" && f.deleted {
		return nil, status.Error(codes.NotFound, "node not found; enroll with an auth key")
	}
	if req.GetAuthKey() != "" && !f.keys[req.GetAuthKey()] {
		return nil, status.Error(codes.Unauthenticated, "auth key denied")
	}
	ch, eph, err := meshproto.NewRegisterChallenge()
	if err != nil {
		return nil, err
	}
	f.seq++
	id := fmt.Sprintf("ch-%d", f.seq)
	f.pending[id], f.ephs[id] = ch, eph
	return &meshpb.GetRegisterChallengeResponse{ChallengeId: id, Challenge: ch.Encode()}, nil
}

func (f *shCoord) RegisterNode(_ context.Context, req *meshpb.RegisterNodeRequest) (*meshpb.RegisterNodeResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ch, ok := f.pending[req.GetChallengeId()]
	eph := f.ephs[req.GetChallengeId()]
	delete(f.pending, req.GetChallengeId())
	key, err := meshproto.ParseNodeKey(req.GetNodeKey())
	if !ok || err != nil || meshproto.OpenRegisterProof(ch, eph, key, req.GetRegisterProof()) != nil {
		return nil, status.Error(codes.Unauthenticated, "proof rejected")
	}
	f.nodeKey = req.GetNodeKey()
	if req.GetAuthKey() == "" {
		f.regs = append(f.regs, fmt.Sprintf("reauth:%d", req.GetNodeId()))
	} else {
		f.regs = append(f.regs, "key:"+req.GetAuthKey())
		f.deleted = false
	}
	resp := &meshpb.RegisterNodeResponse{NodeId: 21, OverlayAddr: "100.64.0.21", ProtocolVersion: meshproto.ProtocolVersion, SessionToken: "sh-session"}
	for _, c := range req.GetCapabilities() {
		if f.offer && c == string(meshproto.CapNodeReauth) {
			resp.Capabilities = append(resp.Capabilities, c)
		}
	}
	return resp, nil
}

func (f *shCoord) PullNetMap(_ *meshpb.PullNetMapRequest, stream meshpb.Coordinator_PullNetMapServer) error {
	f.mu.Lock()
	self := &meshpb.Peer{NodeId: 21, NodeKey: f.nodeKey, OverlayAddr: "100.64.0.21"}
	f.mu.Unlock()
	if err := stream.Send(&meshpb.NetMap{Self: self}); err != nil {
		return err
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

func (f *shCoord) ReportEndpoints(context.Context, *meshpb.ReportEndpointsRequest) (*meshpb.ReportEndpointsResponse, error) {
	return &meshpb.ReportEndpointsResponse{}, nil
}

func (f *shCoord) ListNodes(_ context.Context, req *meshpb.ListNodesRequest) (*meshpb.ListNodesResponse, error) {
	if err := f.session(req.GetSessionToken()); err != nil {
		return nil, err
	}
	return &meshpb.ListNodesResponse{Nodes: []*meshpb.NodeInfo{
		{Id: 21, Name: "pixel-8-pro", OverlayAddr: "100.64.0.21", Online: true, Approved: true},
		{Id: 22, Name: "nas", Os: "linux", OverlayAddr: "100.64.0.22", Approved: true, ApprovedRoutes: []string{"0.0.0.0/0"},
			Services: []*meshpb.PeerService{{Name: "photos", Proto: "tcp", Port: 443}}},
	}}, nil
}

func (f *shCoord) SignOut(context.Context, *meshpb.SignOutRequest) (*meshpb.SignOutResponse, error) {
	f.mu.Lock()
	f.signedOut++
	f.mu.Unlock()
	return &meshpb.SignOutResponse{}, nil
}

func newSelfHostedTestCore(t *testing.T) (*Core, *fakePlatform) {
	t.Helper()
	p := &fakePlatform{}
	// No calabi.net in these tests: a bff that answers nothing.
	return newTestCoreAt(t, "http://127.0.0.1:1", p), p
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// The whole path: an invite link, joined; the key is checked by enrolling and,
// since the server takes the phone back by proof alone, never stored; Connect
// comes back without it; the device list comes from the server.
func TestJoinByInviteThenConnectWithoutTheKey(t *testing.T) {
	useMemoryTUNs(t)
	coord := startSHCoord(t, true, "ck_invite")
	c, p := newSelfHostedTestCore(t)

	code, out := call(t, c, "POST", "/v1/selfhosted/join", fmt.Sprintf(`{"link":%q}`, coord.link("ck_invite")))
	if code != http.StatusOK || out["server"] != coord.addr {
		t.Fatalf("join: %d %v", code, out)
	}
	if fileExists(c.keyPath()) {
		t.Fatal("the key was stored although the server takes the phone back by proof alone")
	}
	if _, st := call(t, c, "GET", "/v1/state", ""); st["signed_in"] != true || st["mode"] != "self_hosted" || st["server"] != coord.addr {
		t.Fatalf("state after join: %v", st)
	}

	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for meshState(t, c)["state"] != stateConnected && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if st := meshState(t, c); st["state"] != stateConnected {
		t.Fatalf("not connected: %v\n%s", st, c.Call("GET", "/v1/logs", nil).Body)
	}
	if len(p.settings()) == 0 || p.settings()[0].Addresses[0] != "100.64.0.21/32" {
		t.Fatalf("VPN = %v", p.settings())
	}
	if regs := coord.registrations(); len(regs) != 2 || regs[0] != "key:ck_invite" || regs[1] != "reauth:21" {
		t.Fatalf("registrations = %v, want the invite once and then proof alone", regs)
	}

	code, nodes := call(t, c, "GET", "/v1/mesh/nodes", "")
	items, _ := nodes["items"].([]any)
	if code != http.StatusOK || len(items) != 2 || items[1].(map[string]any)["name"] != "nas" {
		t.Fatalf("nodes: %d %v", code, nodes)
	}
	// What only calabi.net has is absent, not an error the app would show.
	if code, out := call(t, c, "GET", "/v1/orgs", ""); code != http.StatusOK || len(out["items"].([]any)) != 0 {
		t.Fatalf("orgs: %d %v", code, out)
	}
	// The server's tunnels, read over the live session: no view session opened.
	if code, out := call(t, c, "GET", "/v1/tunnels", ""); code != http.StatusOK || len(out["items"].([]any)) != 2 {
		t.Fatalf("tunnels: %d %v", code, out)
	}
	coord.mu.Lock()
	views := coord.views
	coord.mu.Unlock()
	if views != 0 {
		t.Fatalf("%d view sessions opened while connected", views)
	}
}

// Not connected, the phone still shows its server: its devices, tunnels and
// usage, over one view session opened by proof of the node key — shaped like
// what calabi.net answers, so the screens need nothing of their own.
func TestSelfHostedListsWithoutConnecting(t *testing.T) {
	coord := startSHCoord(t, true, "ck_invite")
	c, _ := newSelfHostedTestCore(t)
	if code, out := call(t, c, "POST", "/v1/selfhosted/join", fmt.Sprintf(`{"link":%q}`, coord.link("ck_invite"))); code != http.StatusOK {
		t.Fatalf("join: %d %v", code, out)
	}

	code, nodes := call(t, c, "GET", "/v1/mesh/nodes", "")
	if code != http.StatusOK || len(nodes["items"].([]any)) != 2 {
		t.Fatalf("nodes: %d %v", code, nodes)
	}

	code, out := call(t, c, "GET", "/v1/tunnels", "")
	items, _ := out["items"].([]any)
	if code != http.StatusOK || len(items) != 2 {
		t.Fatalf("tunnels: %d %v", code, out)
	}
	photos, ssh := items[0].(map[string]any), items[1].(map[string]any)
	if photos["domain"] != "photos.example.com" || photos["status"] != "online" || photos["device_name"] != "nas" ||
		photos["edge_node_id"] != float64(1) || photos["traffic_30d"] != float64(5000) || photos["created_at"] != "2026-09-01T08:00:00Z" {
		t.Errorf("photos = %v", photos)
	}
	// Its device is not connected: what it reported may no longer be served.
	if ssh["edge_host"] != "edge.example.com" || ssh["remote_port"] != float64(2222) || ssh["status"] != "offline" {
		t.Errorf("ssh = %v", ssh)
	}

	code, u := call(t, c, "GET", "/v1/usage/overview?tz=Asia%2FTokyo", "")
	month, _ := u["month"].(map[string]any)
	if code != http.StatusOK || u["plan"] != "self_hosted" || month["used_bytes"] != float64(1000) || month["limit_bytes"] != float64(-1) {
		t.Fatalf("usage: %d %v", code, u)
	}
	if days := u["days"].([]any); len(days) != 2 || days[1].(map[string]any)["bytes"] != float64(990) {
		t.Fatalf("days: %v", u["days"])
	}
	coord.mu.Lock()
	tz, views := coord.usageTZ, coord.views
	coord.mu.Unlock()
	if tz != "Asia/Tokyo" || views != 1 {
		t.Fatalf("time zone %q, %d view sessions; want the viewer's and one session for the three reads", tz, views)
	}

	// The server forgot the session (it restarted): the phone opens another.
	coord.mu.Lock()
	coord.forgotView = "sh-view-1"
	coord.unavailable = "no_database"
	coord.mu.Unlock()
	code, u = call(t, c, "GET", "/v1/usage/overview", "")
	if code != http.StatusOK || u["unavailable"] != "no_database" || u["month"] != nil {
		t.Fatalf("usage without a database: %d %v", code, u)
	}
	coord.mu.Lock()
	views = coord.views
	coord.mu.Unlock()
	if views != 2 {
		t.Fatalf("%d view sessions after the first was refused, want 2", views)
	}
}

// A coordinator too old to take a device back by proof alone cannot open a view
// either: the lists wait for a connection, as before.
func TestSelfHostedListsNeedAConnectionOnOlderCoordinators(t *testing.T) {
	coord := startSHCoord(t, false, "ck_old")
	c, _ := newSelfHostedTestCore(t)
	if code, out := call(t, c, "POST", "/v1/selfhosted/join", fmt.Sprintf(`{"link":%q}`, coord.link("ck_old"))); code != http.StatusOK {
		t.Fatalf("join: %d %v", code, out)
	}
	for _, path := range []string{"/v1/mesh/nodes", "/v1/tunnels", "/v1/usage/overview"} {
		if code, out := call(t, c, "GET", path, ""); code != http.StatusConflict || out["code"] != "not_connected" {
			t.Errorf("%s: %d %v, want not_connected", path, code, out)
		}
	}
}

// Typed in without a fingerprint, a self-signed server is not trusted until a
// person has compared the fingerprint the app shows; then it is pinned.
func TestJoinByHandAsksToConfirmTheFingerprint(t *testing.T) {
	coord := startSHCoord(t, true, "ck_k")
	c, _ := newSelfHostedTestCore(t)

	code, out := call(t, c, "POST", "/v1/selfhosted/probe", fmt.Sprintf(`{"server":%q}`, coord.addr))
	if code != http.StatusOK || out["tls"] != true || out["system_trusted"] != false || out["pin"] != coord.pin {
		t.Fatalf("probe: %d %v", code, out)
	}
	code, out = call(t, c, "POST", "/v1/selfhosted/join", fmt.Sprintf(`{"server":%q,"key":"ck_k"}`, coord.addr))
	if code != http.StatusConflict || out["code"] != "untrusted" || out["pin"] != coord.pin {
		t.Fatalf("join without a pin: %d %v", code, out)
	}
	if c.selfHosted() != nil || len(coord.registrations()) != 0 {
		t.Fatal("an untrusted server was joined, or the key was sent to it")
	}
	code, out = call(t, c, "POST", "/v1/selfhosted/join", fmt.Sprintf(`{"server":%q,"key":"ck_k","pin":%q}`, coord.addr, coord.pin))
	if code != http.StatusOK {
		t.Fatalf("join with the confirmed pin: %d %v", code, out)
	}
	if p := c.selfHosted(); p == nil || p.Trust.Mode != "pin" || len(p.Trust.Pins) != 1 || p.Trust.Pins[0] != coord.pin {
		t.Fatalf("profile = %+v", p)
	}
}

func TestJoinRefusals(t *testing.T) {
	coord := startSHCoord(t, true, "ck_good")
	c, _ := newSelfHostedTestCore(t)

	wrongPin := "sha256:" + fmt.Sprintf("%064x", 1)
	code, out := call(t, c, "POST", "/v1/selfhosted/join", fmt.Sprintf(`{"server":%q,"key":"ck_good","pin":%q}`, coord.addr, wrongPin))
	if code != http.StatusConflict || out["code"] != "pin_mismatch" || out["pin"] != coord.pin {
		t.Errorf("wrong pin: %d %v", code, out)
	}
	code, out = call(t, c, "POST", "/v1/selfhosted/join", fmt.Sprintf(`{"link":%q}`, coord.link("ck_used-up")))
	if code != http.StatusUnauthorized || out["code"] != "key_refused" {
		t.Errorf("refused key: %d %v", code, out)
	}
	for _, body := range []string{`{"link":"https://example.com/join?s=a:1&k=b"}`, `{"server":"no-port","key":"k"}`, `{"server":"h:1"}`} {
		if code, _ := call(t, c, "POST", "/v1/selfhosted/join", body); code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", body, code)
		}
	}
	if c.selfHosted() != nil || fileExists(c.keyPath()) {
		t.Fatal("a refused join left something saved")
	}
}

// A coordinator that does not take devices back by proof alone (older than
// 1.13) keeps getting the key, so the phone keeps it.
func TestJoinAnOlderCoordinatorKeepsTheKey(t *testing.T) {
	useMemoryTUNs(t)
	coord := startSHCoord(t, false, "ck_old")
	c, _ := newSelfHostedTestCore(t)
	if code, out := call(t, c, "POST", "/v1/selfhosted/join", fmt.Sprintf(`{"link":%q}`, coord.link("ck_old"))); code != http.StatusOK {
		t.Fatalf("join: %d %v", code, out)
	}
	if c.authKey() != "ck_old" {
		t.Fatal("the key was not kept for a coordinator that needs it on every reconnect")
	}
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "connected", func() bool { return meshState(t, c)["state"] == stateConnected })
	if regs := coord.registrations(); len(regs) != 2 || regs[1] != "key:ck_old" {
		t.Fatalf("registrations = %v, want the key both times", regs)
	}
}

// A server that will not take the phone back — the device was deleted, and the
// phone has no key left — is a state the app shows, not a retry loop.
func TestDeletedDeviceNeedsANewInvite(t *testing.T) {
	useMemoryTUNs(t)
	coord := startSHCoord(t, true, "ck_invite")
	c, _ := newSelfHostedTestCore(t)
	if code, out := call(t, c, "POST", "/v1/selfhosted/join", fmt.Sprintf(`{"link":%q}`, coord.link("ck_invite"))); code != http.StatusOK {
		t.Fatalf("join: %d %v", code, out)
	}
	coord.mu.Lock()
	coord.deleted = true
	coord.mu.Unlock()
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "needs_invite", func() bool { return meshState(t, c)["state"] == stateNeedsInvite })
	before := len(coord.registrations())
	time.Sleep(1500 * time.Millisecond)
	if n := len(coord.registrations()); n != before {
		t.Fatalf("kept trying after the server said no: %d registrations, then %d", before, n)
	}
}

// A server whose certificate changed is not connected to — nothing, not even
// the proof of the node key, goes to it — until a person has compared the new
// fingerprint and confirmed it; the app gets both fingerprints to show.
func TestCertificateChangeWaitsForAPerson(t *testing.T) {
	useMemoryTUNs(t)
	coord := startSHCoord(t, true, "ck_invite")
	c, _ := newSelfHostedTestCore(t)
	if code, out := call(t, c, "POST", "/v1/selfhosted/join", fmt.Sprintf(`{"link":%q}`, coord.link("ck_invite"))); code != http.StatusOK {
		t.Fatalf("join: %d %v", code, out)
	}
	newPin := coord.rotateCert(t)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "cert_changed", func() bool { return meshState(t, c)["state"] == stateCertChanged })
	if st := meshState(t, c); st["cert_presented"] != newPin || st["cert_pinned"] != coord.pin {
		t.Fatalf("state = %v, want the new fingerprint %s next to the trusted %s", st, newPin, coord.pin)
	}
	if regs := coord.registrations(); len(regs) != 1 {
		t.Fatalf("registrations = %v: the phone talked to a server it does not trust", regs)
	}

	// A confirmation covers what the server presents now, nothing else.
	code, out := call(t, c, "POST", "/v1/selfhosted/trust", fmt.Sprintf(`{"pin":%q}`, coord.pin))
	if code != http.StatusConflict || out["code"] != "pin_mismatch" || out["pin"] != newPin {
		t.Fatalf("trusting a fingerprint the server does not present: %d %v", code, out)
	}
	if code, out := call(t, c, "POST", "/v1/selfhosted/trust", fmt.Sprintf(`{"pin":%q}`, newPin)); code != http.StatusOK {
		t.Fatalf("trust: %d %v", code, out)
	}
	if p := c.selfHosted(); p == nil || p.Trust.Mode != "pin" || len(p.Trust.Pins) != 1 || p.Trust.Pins[0] != newPin {
		t.Fatalf("profile = %+v", p)
	}
	waitFor(t, "connected", func() bool { return meshState(t, c)["state"] == stateConnected })
	if regs := coord.registrations(); regs[len(regs)-1] != "reauth:21" {
		t.Fatalf("registrations = %v, want the phone back by proof alone", regs)
	}
	if st := meshState(t, c); st["cert_presented"] != nil {
		t.Fatalf("connected, still reporting a changed certificate: %v", st)
	}
}

// A self-hosted server that is down is retried on a growing backoff, like
// calabi.net, not every two seconds for as long as it stays down.
func TestSelfHostedRetriesBackOff(t *testing.T) {
	useMemoryTUNs(t)
	coord := startSHCoord(t, true, "ck_invite")
	c, _ := newSelfHostedTestCore(t)
	if code, out := call(t, c, "POST", "/v1/selfhosted/join", fmt.Sprintf(`{"link":%q}`, coord.link("ck_invite"))); code != http.StatusOK {
		t.Fatalf("join: %d %v", code, out)
	}
	coord.stop()
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "a second, longer wait", func() bool {
		return strings.Contains(string(c.Call("GET", "/v1/logs", nil).Body), "backoff=2s")
	})
	if st := meshState(t, c)["state"]; st != stateRetrying {
		t.Fatalf("state = %v, want retrying: a server that is down is not a changed certificate", st)
	}
}

// Signing out tells the server, forgets the connection, and keeps the phone's
// own key — joining the same server again is the same device.
func TestSignOutForgetsTheServer(t *testing.T) {
	coord := startSHCoord(t, true, "ck_invite")
	c, _ := newSelfHostedTestCore(t)
	if code, out := call(t, c, "POST", "/v1/selfhosted/join", fmt.Sprintf(`{"link":%q}`, coord.link("ck_invite"))); code != http.StatusOK {
		t.Fatalf("join: %d %v", code, out)
	}
	if code, _ := call(t, c, "PUT", "/v1/settings", `{"exit_node":"home-server"}`); code != http.StatusOK {
		t.Fatalf("choose the exit device: %d", code)
	}
	if code, _ := call(t, c, "POST", "/v1/auth/logout", ""); code != http.StatusOK {
		t.Fatalf("logout: %d", code)
	}
	// Its exit device is a device of the server left.
	if _, s := call(t, c, "GET", "/v1/settings", ""); s["exit_node"] != "" {
		t.Fatalf("after signing out of the server, exit = %v; want none", s["exit_node"])
	}
	coord.mu.Lock()
	signedOut := coord.signedOut
	coord.mu.Unlock()
	if signedOut != 1 {
		t.Fatalf("the server was told %d times, want once", signedOut)
	}
	if c.selfHosted() != nil {
		t.Fatal("still joined after signing out")
	}
	if !fileExists(filepath.Join(c.cfg.StateDir, "mesh.key")) {
		t.Fatal("the phone's own key went with the sign-out")
	}
	if _, st := call(t, c, "GET", "/v1/state", ""); st["signed_in"] != false {
		t.Fatalf("state after sign-out: %v", st)
	}
}

// One network at a time: joining while signed in to calabi.net asks first, and
// with replace signs out of calabi.net.
func TestJoinWhileSignedInToCalabiNet(t *testing.T) {
	coord := startSHCoord(t, true, "ck_invite")
	bff := &fakeBFF{}
	c := newTestCore(t, bff, &fakePlatform{})
	signIn(t, c)

	code, out := call(t, c, "POST", "/v1/selfhosted/join", fmt.Sprintf(`{"link":%q}`, coord.link("ck_invite")))
	if code != http.StatusConflict || out["code"] != "signed_in" {
		t.Fatalf("join while signed in: %d %v", code, out)
	}
	code, out = call(t, c, "POST", "/v1/selfhosted/join", fmt.Sprintf(`{"link":%q,"replace":true}`, coord.link("ck_invite")))
	if code != http.StatusOK {
		t.Fatalf("join with replace: %d %v", code, out)
	}
	bff.mu.Lock()
	logouts := len(bff.logouts)
	bff.mu.Unlock()
	if logouts != 1 {
		t.Fatalf("calabi.net logouts = %d, want 1", logouts)
	}
	if _, st := call(t, c, "GET", "/v1/state", ""); st["mode"] != "self_hosted" || st["email"] != nil {
		t.Fatalf("state: %v", st)
	}
}
