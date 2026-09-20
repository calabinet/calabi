package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/calabinet/calabi/apps/client/internal/creds"
	"github.com/calabinet/calabi/apps/client/internal/mesh"
	"github.com/calabinet/calabi/apps/client/internal/selfhosted"
	"github.com/calabinet/calabi/apps/client/internal/status"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// isolateDataDir gives the test its own data directory and credentials file:
// the console's tunnels.yaml, the reauth record and the lock all live there.
func isolateDataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	creds.SetDataDir(dir)
	t.Cleanup(func() { creds.SetDataDir("") })
	t.Setenv("CALABI_CONFIG", filepath.Join(dir, "config.json"))
	t.Setenv("CALABI_MODE", "")
	t.Setenv("CALABI_DAEMON_CONFIG", "")
	t.Setenv("CALABI_SERVER", "")
	t.Setenv("CALABI_INSECURE", "")
	t.Setenv("CALABI_EDGE_CA_FILE", "")
	t.Setenv("CALABI_API_KEY", "")
	t.Setenv("CALABI_TOKEN", "")
	// The mesh key (os.UserConfigDir) and the daemon log (the cache dir) too.
	for _, v := range []string{"APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_CACHE_HOME"} {
		t.Setenv(v, filepath.Join(dir, strings.ToLower(v)))
	}
	return dir
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// consoleCall is one request to the daemon's console.
func consoleCall(t *testing.T, base, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, base+path, rd)
	if token != "" {
		req.Header.Set("X-Local-Token", token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// waitFor polls until ok or the deadline.
func waitFor(t *testing.T, what string, d time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// meshOffTheNetwork keeps every mesh runner the local daemon builds off this
// machine's network: its data plane never starts (no tun device), so the
// daemon reads the coordinator over view sessions — as with the mesh off.
func meshOffTheNetwork(t *testing.T) {
	t.Helper()
	localMeshTuning = meshLoopTuning{
		startDP: func() (*meshDataPlane, error) { return nil, errors.New("no data plane in tests") },
	}
	t.Cleanup(func() { localMeshTuning = meshLoopTuning{} })
}

// The desktop's whole way onto a self-hosted server and back, in one process:
// the calabi.net daemon's console joins the machine to a coordinator (after the
// person confirms its certificate), the daemon starts again as the local one on
// the SAME console address and serves tunnels on the edge the coordinator names
// — with the mesh on or off — follows that edge to a new certificate without
// asking anyone, and leaving brings the calabi.net daemon back.
func TestConsoleSwitchesBetweenCalabiNetAndASelfHostedServer(t *testing.T) {
	dir := isolateDataDir(t)
	meshOffTheNetwork(t)
	addr := freePort(t)
	t.Setenv("CALABI_STATUS_ADDR", addr)
	t.Setenv("CALABI_BFF_CONSOLE", "http://127.0.0.1:1") // nowhere: the platform daemon waits for a sign-in
	coord := startFakeSHCoord(t, true, "invite-1")
	edge := startFakeGrantEdge(t, coord.grantPub())
	coord.setEdge(edge.addr, edge.pin)
	base := "http://" + addr

	done := make(chan int, 1)
	go func() { done <- runDaemon(nil) }()
	t.Cleanup(func() {
		select {
		case restartCh <- struct{}{}: // ends the daemon without asking for another
		default:
		}
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Error("the daemon did not stop")
		}
	})

	var st map[string]any
	waitFor(t, "the calabi.net daemon's console", 15*time.Second, func() bool {
		_, st = consoleCall(t, base, "GET", "/v1/selfhosted", "", nil)
		return st["mode"] == "platform"
	})
	if st["can_join"] != true {
		t.Fatalf("platform status: %v", st)
	}
	token := func() string {
		_, tok := consoleCall(t, base, "GET", "/v1/local-token", "", nil)
		s, _ := tok["token"].(string)
		return s
	}

	// Typed in without the fingerprint: a person confirms it first, and nothing
	// is spent meanwhile.
	join := map[string]any{"mesh": map[string]any{"server": coord.addr, "key": "invite-1"}}
	code, res := consoleCall(t, base, "POST", "/v1/selfhosted/join", token(), join)
	if code != http.StatusConflict || res["code"] != "untrusted" || res["pin"] != coord.pin || res["part"] != "mesh" {
		t.Fatalf("join an unknown certificate: %d %v; want untrusted with the coordinator's pin", code, res)
	}
	if regs := coord.registrations(); len(regs) != 0 {
		t.Fatalf("the invite was used before the certificate was confirmed: %v", regs)
	}
	join = map[string]any{"mesh": map[string]any{"server": coord.addr, "key": "invite-1", "pin": coord.pin}}
	if code, res = consoleCall(t, base, "POST", "/v1/selfhosted/join", token(), join); code != http.StatusOK || res["switching"] != true {
		t.Fatalf("join: %d %v", code, res)
	}

	// The local daemon, on the same address, with tunnels on the coordinator's edge.
	connected := func() bool {
		_, st = consoleCall(t, base, "GET", "/v1/selfhosted", "", nil)
		e, _ := st["edge"].(map[string]any)
		return st["mode"] == "self_hosted" && e != nil && e["connected"] == true
	}
	waitFor(t, "the local daemon connected to the edge", 20*time.Second, connected)
	e := st["edge"].(map[string]any)
	m, _ := st["mesh"].(map[string]any)
	if e["server"] != edge.addr || e["state"] != "connected" || m == nil || m["server"] != coord.addr || st["can_leave"] != true {
		t.Fatalf("self-hosted status: %v", st)
	}
	key, err := mesh.LoadOrCreateKey(defaultMeshKeyPath())
	if err != nil {
		t.Fatal(err)
	}
	if nodes := edge.provedNodes(); len(nodes) == 0 || nodes[0] != key.Public() {
		t.Fatalf("the edge's sessions proved %v; want this device's node key %v", nodes, key.Public())
	}
	if c, _ := creds.Load(); c == nil || c.Mode != clientModeStandalone {
		t.Fatalf("mode after joining: %+v", c)
	}
	yml, err := os.ReadFile(filepath.Join(dir, "tunnels.yaml"))
	if err != nil || !strings.Contains(string(yml), coord.pin) || strings.Contains(string(yml), "server:") || strings.Contains(string(yml), edge.pin) {
		t.Fatalf("the console's tunnels.yaml should name the coordinator and nothing about the edge: %v\n%s", err, yml)
	}

	// The mesh off: the device leaves the meshnet and keeps its tunnels, and it
	// stays off across restarts.
	if code, res = consoleCall(t, base, "POST", "/v1/mesh/down", token(), nil); code != http.StatusOK {
		t.Fatalf("mesh down: %d %v", code, res)
	}
	if yml, _ = os.ReadFile(filepath.Join(dir, "tunnels.yaml")); strings.Contains(string(yml), "enabled: true") {
		t.Fatalf("the mesh is off but the config still turns it on:\n%s", yml)
	}
	before := edge.sessions()
	edge.dropAll()
	waitFor(t, "tunnels back on the edge with the mesh off", 20*time.Second, func() bool { return edge.sessions() > before && connected() })
	if m := st["mesh"].(map[string]any); m["state"] != "paused" {
		t.Fatalf("mesh state with the mesh off: %v", m)
	}
	if code, res = consoleCall(t, base, "POST", "/v1/mesh/up", token(), nil); code != http.StatusOK {
		t.Fatalf("mesh up: %d %v", code, res)
	}
	if yml, _ = os.ReadFile(filepath.Join(dir, "tunnels.yaml")); !strings.Contains(string(yml), "enabled: true") {
		t.Fatalf("the mesh is on again but the config does not say so:\n%s", yml)
	}

	// The edge changes its certificate: the coordinator names the new one, and
	// the device follows it with nobody asked to confirm anything.
	before = edge.sessions()
	coord.setEdge(edge.addr, edge.rotateCert(t))
	waitFor(t, "a connection with the edge's new certificate", 20*time.Second, func() bool { return edge.sessions() > before && connected() })

	// Leave: back to the calabi.net daemon, on the same address.
	if code, res = consoleCall(t, base, "POST", "/v1/selfhosted/leave", token(), nil); code != http.StatusOK {
		t.Fatalf("leave: %d %v", code, res)
	}
	waitFor(t, "the calabi.net daemon again", 20*time.Second, func() bool {
		_, st = consoleCall(t, base, "GET", "/v1/selfhosted", "", nil)
		return st["mode"] == "platform"
	})
	if _, err := os.Stat(filepath.Join(dir, "tunnels.yaml")); !os.IsNotExist(err) {
		t.Fatalf("the console's tunnels.yaml survived leaving: %v", err)
	}
	if c, _ := creds.Load(); c == nil || c.Mode != "" {
		t.Fatalf("mode after leaving: %+v", c)
	}
	coord.mu.Lock()
	signedOut := coord.signedOut
	coord.mu.Unlock()
	if signedOut != 1 {
		t.Fatalf("the coordinator was told %d times that the device left, want once", signedOut)
	}
}

// Signed in to calabi.net, the join is refused until the person signs out: one
// network at a time.
func TestJoinWhileSignedInAsksToSignOut(t *testing.T) {
	isolateDataDir(t)
	if _, err := creds.MintLocalToken(); err != nil {
		t.Fatal(err)
	}
	tok, _ := creds.LoadLocalToken()
	if err := creds.Save(&creds.Config{AccessToken: "jwt", User: struct {
		ID    int64  `json:"id"`
		Email string `json:"email"`
	}{Email: "kenji@example.com"}}); err != nil {
		t.Fatal(err)
	}
	h := &platformSelfHosted{logger: quietTestLogger()}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/selfhosted/join", strings.NewReader(`{"mesh":{"link":"calabi://join?v=1&s=127.0.0.1:1&k=x"}}`))
	req.Header.Set("X-Local-Token", tok)
	h.handleJoin(rec, req)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), `"signed_in"`) {
		t.Fatalf("join while signed in: %d %s", rec.Code, rec.Body)
	}
	h.agentMode = true
	rec = httptest.NewRecorder()
	h.handleJoin(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("join on an api-key service: %d %s", rec.Code, rec.Body)
	}
}

func meshJoinReq(link string) joinRequest {
	var in joinRequest
	_ = json.Unmarshal([]byte(fmt.Sprintf(`{"mesh":{"link":%q}}`, link)), &in)
	return in
}

// Joining a coordinator enrolls with it — the one check of a key that means
// anything — and keeps the key only where the coordinator cannot take the
// device back without it.
func TestJoinMeshKeepsTheKeyOnlyWhereItIsNeeded(t *testing.T) {
	isolateDataDir(t)
	ctx := context.Background()

	coord := startFakeSHCoord(t, true, "invite-1")
	next, fail := joinSelfHosted(ctx, localConfig{}, meshJoinReq(coord.link("invite-1")))
	if fail != nil {
		t.Fatalf("join: %v", fail.body)
	}
	m := next.Mesh
	if !m.Enabled || m.Coord != coord.addr || m.Trust != "pin" || len(m.Pins) != 1 || m.Pins[0] != coord.pin || m.AuthKey != "" {
		t.Fatalf("mesh block: %+v", m)
	}
	if rec := loadMeshReauth(coord.addr); rec.NodeID != 21 || !rec.Reauth {
		t.Fatalf("reauth record: %+v", rec)
	}

	old := startFakeSHCoord(t, false, "invite-2")
	next, fail = joinSelfHosted(ctx, localConfig{}, meshJoinReq(old.link("invite-2")))
	if fail != nil || next.Mesh.AuthKey != "invite-2" {
		t.Fatalf("an older coordinator: %v %+v; want the key kept", fail, next.Mesh)
	}

	// Already joined: asked before replacing; a refused key says so.
	if _, fail = joinSelfHosted(ctx, next, meshJoinReq(coord.link("invite-1"))); fail == nil || fail.body["code"] != "joined" {
		t.Fatalf("joining while joined: %v", fail)
	}
	in := meshJoinReq(coord.link("used-up"))
	in.Replace = true
	if _, fail = joinSelfHosted(ctx, next, in); fail == nil || fail.body["code"] != "key_refused" {
		t.Fatalf("a refused key: %v", fail)
	}
	// Typed in by hand without the fingerprint: a person confirms it first.
	in = joinRequest{}
	_ = json.Unmarshal([]byte(fmt.Sprintf(`{"mesh":{"server":%q,"key":"invite-1"}}`, coord.addr)), &in)
	if _, fail = joinSelfHosted(ctx, localConfig{}, in); fail == nil || fail.body["code"] != "untrusted" || fail.body["pin"] != coord.pin {
		t.Fatalf("an unconfirmed certificate: %v", fail)
	}
}

func shSupervisor(t *testing.T, cfg localConfig, managed bool) *localSupervisor {
	t.Helper()
	path := managedConfigPath()
	if !managed {
		path = filepath.Join(t.TempDir(), "mine.yaml")
	}
	if err := writeLocalConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	return newLocalSupervisor(quietTestLogger(), cfg, path, nil)
}

// Once the coordinator takes the device back by proof alone, the console's
// config forgets the key; a hand-written one is left as its author wrote it.
func TestRecordReauthDropsTheKeyFromTheConsolesConfig(t *testing.T) {
	isolateDataDir(t)
	for _, managed := range []bool{true, false} {
		sv := shSupervisor(t, localConfig{Mesh: meshConfig{Enabled: true, Coord: "coord.example:7012", AuthKey: "k"}}, managed)
		m := newLocalMesh(quietTestLogger(), sv, managed, nil)
		m.recordReauth("coord.example:7012")(21, true)
		b, _ := os.ReadFile(sv.configPath)
		if has := strings.Contains(string(b), "auth_key"); has == managed {
			t.Errorf("managed=%v: auth_key in the file = %v\n%s", managed, has, b)
		}
		if rec := loadMeshReauth("coord.example:7012"); !rec.canRejoin() {
			t.Errorf("managed=%v: record %+v", managed, rec)
		}
		// Without the key the mesh still starts: the record is enough.
		if r := m.build(); managed && r == nil {
			t.Error("a device with a reauth record and no key did not get a mesh runner")
		}
	}
}

// The meshnet's tunnels, traffic and devices are readable without connecting:
// the device proves its key for a view session.
func TestSelfHostedListsWithoutConnecting(t *testing.T) {
	isolateDataDir(t)
	coord := startFakeSHCoord(t, true, "invite-1")
	cfg := localConfig{Mesh: meshConfig{Enabled: true, Coord: coord.addr, Trust: "pin", Pins: []string{coord.pin},
		KeyFile: filepath.Join(t.TempDir(), "mesh.key")}}
	sv := shSupervisor(t, cfg, true)
	if err := saveMeshReauth(meshReauthRecord{Coord: coord.addr, NodeID: 21, Reauth: true}); err != nil {
		t.Fatal(err)
	}
	h := &localSelfHosted{logger: quietTestLogger(), sv: sv, mesh: newLocalMesh(quietTestLogger(), sv, true, nil), managed: true}

	get := func(path string) (int, map[string]any) {
		rec := httptest.NewRecorder()
		mux := http.NewServeMux()
		h.register(mux)
		mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	code, out := get("/v1/selfhosted/tunnels")
	items, _ := out["items"].([]any)
	if code != http.StatusOK || len(items) != 2 {
		t.Fatalf("tunnels: %d %v", code, out)
	}
	if ssh := items[1].(map[string]any); ssh["status"] != "offline" || ssh["node_name"] != "old-laptop" {
		t.Fatalf("a tunnel of an offline device: %v", ssh)
	}
	code, out = get("/v1/selfhosted/usage?tz=America/New_York")
	month, _ := out["month"].(map[string]any)
	if code != http.StatusOK || month["tunnel_bytes"] != float64(700) || month["relay_bytes"] != float64(300) {
		t.Fatalf("usage: %d %v", code, out)
	}
	coord.mu.Lock()
	tz, views := coord.usageTZ, coord.views
	coord.mu.Unlock()
	if tz != "America/New_York" || views != 1 {
		t.Fatalf("usage asked for %q over %d view sessions; want the viewer's zone over one", tz, views)
	}
	code, out = get("/v1/mesh/nodes")
	nodes, _ := out["items"].([]any)
	if code != http.StatusOK || len(nodes) != 2 || nodes[1].(map[string]any)["disabled"] != true {
		t.Fatalf("nodes: %d %v", code, out)
	}
	// No coordinator configured: said so, not an empty list.
	sv2 := shSupervisor(t, localConfig{}, true)
	h.sv, h.mesh = sv2, newLocalMesh(quietTestLogger(), sv2, true, nil)
	if code, out = get("/v1/selfhosted/tunnels"); code != http.StatusConflict || out["code"] != "no_mesh" {
		t.Fatalf("no coordinator: %d %v", code, out)
	}
}

// A coordinator whose certificate the node's trust refuses is reported with
// both fingerprints; one that is merely down is not.
func TestCoordinatorCertificateChangeIsReported(t *testing.T) {
	isolateDataDir(t)
	coord := startFakeSHCoord(t, true)
	was := coord.pin
	now := coord.rotateCert(t)
	r := newMeshRunner(quietTestLogger(), meshConfig{Enabled: true, Coord: coord.addr, Trust: "pin", Pins: []string{was}, AuthKey: "k"})
	r.certs = &certWatch{}
	r.checkCoordCert(context.Background())
	if p, pinned := r.coordCert(); p != now || pinned != was {
		t.Fatalf("certificate change: presented %q pinned %q; want %q / %q", p, pinned, now, was)
	}
	// A session that registered was not stopped by the certificate.
	r.lastRegistered = true
	r.checkCoordCert(context.Background())
	if p, _ := r.coordCert(); p != "" {
		t.Fatalf("after a registered session: still reporting %q", p)
	}
	// Nobody answering is the network, not the certificate.
	r = newMeshRunner(quietTestLogger(), meshConfig{Enabled: true, Coord: freePort(t), Trust: "pin", Pins: []string{was}, AuthKey: "k"})
	r.certs = &certWatch{}
	r.checkCoordCert(context.Background())
	if p, _ := r.coordCert(); p != "" {
		t.Fatalf("a coordinator that is down reported certificate %q", p)
	}
}

func TestArgsForMode(t *testing.T) {
	got := argsForMode([]string{"--edge-region", "us", "--status-addr", "127.0.0.1:7500", "--name=box", "-status-addr=127.0.0.1:7600"})
	want := []string{"--status-addr", "127.0.0.1:7500", "-status-addr=127.0.0.1:7600"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("argsForMode = %v, want %v", got, want)
	}
}

// Mesh settings on a self-hosted device are written to its config and applied;
// a forwarding role this host cannot honour is refused, as on calabi.net.
func TestLocalMeshSettingsPersist(t *testing.T) {
	isolateDataDir(t)
	sv := shSupervisor(t, localConfig{Mesh: meshConfig{Enabled: true, Coord: "coord.example:7012", AuthKey: "k"}}, true)
	h := &localSelfHosted{logger: quietTestLogger(), sv: sv, mesh: newLocalMesh(quietTestLogger(), sv, true, nil), managed: true}
	post := func(body string) (int, string) {
		rec := httptest.NewRecorder()
		h.handleAdvertiseSet(rec, httptest.NewRequest("POST", "/v1/mesh/advertise", strings.NewReader(body)))
		return rec.Code, rec.Body.String()
	}
	if code, body := post(`{"routes":[],"advertise_exit_node":false,"exit_node":"nas","block_incoming":true,"accept_routes":true,"route_excludes":["192.168.1.22"]}`); code != http.StatusOK {
		t.Fatalf("save: %d %s", code, body)
	}
	b, _ := os.ReadFile(sv.configPath)
	for _, want := range []string{"exit_node: nas", "block_incoming: true", "accept_routes: true", "192.168.1.22/32"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("config lacks %q:\n%s", want, b)
		}
	}
	if !mesh.SubnetRouterSupported() {
		if code, body := post(`{"routes":["192.168.1.0/24"]}`); code != http.StatusBadRequest {
			t.Fatalf("advertising a subnet where this host cannot forward: %d %s", code, body)
		}
	}
}

// When a daemon's console reports done, its port is free: the daemon that
// follows a switch binds the same address instead of falling back to the next
// port, which would leave the open page talking to nobody.
func TestDaemonConsoleReleasesItsPort(t *testing.T) {
	isolateDataDir(t)
	for i := 0; i < 5; i++ {
		addr := freePort(t)
		t.Setenv("CALABI_STATUS_ADDR", addr)
		ctx, cancel := context.WithCancel(context.Background())
		url, done := startDaemonConsole(ctx, quietTestLogger(), status.New("test", ""), func(*http.ServeMux) {})
		if url != "http://"+addr {
			t.Fatalf("console at %q, want %s", url, addr)
		}
		cancel()
		<-done
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatalf("round %d: the port is still held after done: %v", i, err)
		}
		ln.Close()
	}
}

// Moving a self-hosted device to another coordinator from its console tells the
// old one it left — as the node the old one knew, whose record the join is
// about to replace.
func TestJoinAnotherCoordinatorSignsOutOfTheOld(t *testing.T) {
	isolateDataDir(t)
	old := startFakeSHCoord(t, true)
	next := startFakeSHCoord(t, true, "invite-2")
	keyFile := filepath.Join(t.TempDir(), "mesh.key")
	sv := shSupervisor(t, localConfig{Mesh: meshConfig{Enabled: true, Coord: old.addr, Trust: "pin", Pins: []string{old.pin}, KeyFile: keyFile}}, true)
	if err := saveMeshReauth(meshReauthRecord{Coord: old.addr, NodeID: 21, Reauth: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := creds.MintLocalToken(); err != nil {
		t.Fatal(err)
	}
	tok, _ := creds.LoadLocalToken()
	h := &localSelfHosted{logger: quietTestLogger(), sv: sv, mesh: newLocalMesh(quietTestLogger(), sv, true, nil), managed: true}
	t.Cleanup(func() {
		time.Sleep(400 * time.Millisecond) // the restart the join asked for, which no daemon is here to take
		takeDaemonRestart()
	})

	mux := http.NewServeMux()
	h.register(mux)
	body := fmt.Sprintf(`{"mesh":{"link":%q},"replace":true}`, next.link("invite-2"))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/selfhosted/join", strings.NewReader(body))
	req.Header.Set("X-Local-Token", tok)
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("join: %d %s", rec.Code, rec.Body)
	}
	old.mu.Lock()
	signedOut := old.signedOut
	old.mu.Unlock()
	if signedOut != 1 || strings.Join(old.registrations(), ",") != "reauth:21" {
		t.Fatalf("the old coordinator: %d sign-outs after %v; want one, by proof as node 21", signedOut, old.registrations())
	}
	if c := sv.config().Mesh; c.Coord != next.addr || c.Pins[0] != next.pin {
		t.Fatalf("mesh block after the move: %+v", c)
	}
}

// A join that stops for the coordinator's certificate has spent nothing: the
// one-time invite is used only once the certificate is settled.
func TestJoinSpendsTheInviteLast(t *testing.T) {
	isolateDataDir(t)
	ctx := context.Background()
	coord := startFakeSHCoord(t, true, "invite-1")
	in := joinRequest{Mesh: &joinMesh{Server: coord.addr, Key: "invite-1"}}
	if _, fail := joinSelfHosted(ctx, localConfig{}, in); fail == nil || fail.body["code"] != "untrusted" || fail.body["part"] != "mesh" {
		t.Fatalf("an unconfirmed certificate: %v", fail)
	}
	_, otherPin := testSelfSigned(t, "not the coordinator")
	in.Mesh.Pin = otherPin
	if _, fail := joinSelfHosted(ctx, localConfig{}, in); fail == nil || fail.body["code"] != "pin_mismatch" {
		t.Fatalf("another certificate's pin: %v", fail)
	}
	if regs := coord.registrations(); len(regs) != 0 {
		t.Fatalf("the invite was used before the certificate was settled: %v", regs)
	}
	in.Mesh.Pin = coord.pin
	next, fail := joinSelfHosted(ctx, localConfig{}, in)
	if fail != nil || next.Mesh.Coord != coord.addr {
		t.Fatalf("join: %v %+v", fail, next)
	}
	if regs := coord.registrations(); strings.Join(regs, ",") != "key:invite-1" {
		t.Fatalf("registrations: %v", regs)
	}
	// An invite link without a fingerprint takes the one a person confirmed.
	link := "calabi://join?v=1&s=" + coord.addr + "&k=invite-1"
	in = joinRequest{Mesh: &joinMesh{Link: link, Pin: coord.pin}}
	if _, fail := joinSelfHosted(ctx, localConfig{}, in); fail != nil {
		t.Fatalf("a link without a fingerprint, confirmed: %v", fail.body)
	}
	in.Mesh.Pin = ""
	if _, fail := joinSelfHosted(ctx, localConfig{}, in); fail == nil || fail.body["code"] != "untrusted" {
		t.Fatalf("a link without a fingerprint, unconfirmed: %v", fail)
	}
}

// A hand-written config names the coordinator and a key. With its mesh off,
// nothing joins it — but tunnels need it joined, so the first read does, once;
// later ones prove the node key. The file is left as its author wrote it.
func TestHandWrittenConfigJoinsWithItsKeyWhenTheMeshIsOff(t *testing.T) {
	isolateDataDir(t)
	ctx := context.Background()
	coord := startFakeSHCoord(t, true, "fleet-key")
	coord.setEdge("edge.example.com:7443", testPinA)
	cfg := localConfig{Mesh: meshConfig{Coord: coord.addr, AuthKey: "fleet-key", Trust: "pin", Pins: []string{coord.pin},
		KeyFile: filepath.Join(t.TempDir(), "mesh.key")}}
	sv := shSupervisor(t, cfg, false)
	m := newLocalMesh(quietTestLogger(), sv, false, nil)
	if m.configured() || !m.joined() {
		t.Fatalf("configured=%v joined=%v; want joined with the mesh off", m.configured(), m.joined())
	}
	for i := 0; i < 2; i++ {
		acc, err := fetchEdgeAccess(ctx, m.read)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if len(acc.Edges) != 1 || acc.Edges[0].Addr != "edge.example.com:7443" || acc.Edges[0].Pin != testPinA || len(acc.Grant) == 0 {
			t.Fatalf("read %d: %+v", i, acc)
		}
	}
	if regs := coord.registrations(); strings.Join(regs, ",") != "key:fleet-key" {
		t.Fatalf("registrations: %v; want one join by the key", regs)
	}
	if rec := loadMeshReauth(coord.addr); !rec.canRejoin() {
		t.Fatalf("no record of which node this device is: %+v", rec)
	}
	if b, _ := os.ReadFile(sv.configPath); !strings.Contains(string(b), "auth_key: fleet-key") {
		t.Fatalf("the hand-written file was changed:\n%s", b)
	}
}

// Why a device has no tunnels, in a word for the console: "wait" and "join
// again" share a gRPC code, and only the message tells them apart.
func TestEdgeProblem(t *testing.T) {
	wrap := func(err error) error { return fmt.Errorf("edge access: %w", err) }
	for _, tc := range []struct {
		err  error
		want string
	}{
		{wrap(grpcstatus.Error(codes.FailedPrecondition, meshproto.AwaitingApproval)), "awaiting_approval"},
		{wrap(grpcstatus.Error(codes.FailedPrecondition, "node signed out")), "needs_invite"},
		{wrap(grpcstatus.Error(codes.NotFound, "node not found")), "needs_invite"},
		{wrap(grpcstatus.Error(codes.PermissionDenied, "node is disabled")), "disabled"},
		{wrap(grpcstatus.Error(codes.Unavailable, "connection refused")), ""},
		{errNoEdge, "no_edge"},
		{errNoGrant, "no_edge"},
		{errNoMesh, "not_joined"},
		{wrap(selfhosted.ErrCannotView), "connecting"},
		{errors.New("dial: refused"), ""},
		{nil, ""},
	} {
		if got := edgeProblem(tc.err); got != tc.want {
			t.Errorf("edgeProblem(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

// A device with its mesh switched off still serves tunnels, and still reports
// them — over a view session — so the network's tunnel list and traffic keep
// counting it.
func TestTunnelsAreReportedWithTheMeshOff(t *testing.T) {
	isolateDataDir(t)
	coord := startFakeSHCoord(t, true)
	cfg := localConfig{Mesh: meshConfig{Coord: coord.addr, Trust: "pin", Pins: []string{coord.pin},
		KeyFile: filepath.Join(t.TempDir(), "mesh.key")}}
	sv := shSupervisor(t, cfg, true)
	if err := saveMeshReauth(meshReauthRecord{Coord: coord.addr, NodeID: 21, Reauth: true}); err != nil {
		t.Fatal(err)
	}
	meter := mesh.NewTunnelMeter(func() []mesh.TunnelState {
		return []mesh.TunnelState{{Name: "photos", Type: "http", PublicAddr: "u000001.tunnels.example.com", Status: "online", Instance: "1", BytesIn: 42}}
	})
	m := newLocalMesh(quietTestLogger(), sv, true, meter)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)
	defer m.Stop()
	if m.runner() != nil {
		t.Fatal("the mesh is off, yet a runner started")
	}
	waitFor(t, "a tunnel report", 5*time.Second, func() bool {
		coord.mu.Lock()
		defer coord.mu.Unlock()
		return len(coord.reports) > 0
	})
	coord.mu.Lock()
	defer coord.mu.Unlock()
	if r := coord.reports[0]; len(r) != 1 || r[0].GetName() != "photos" || r[0].GetBytesIn() != 42 {
		t.Fatalf("report: %v", r)
	}
	if !strings.HasPrefix(coord.reportTokens[0], "sh-view-") {
		t.Fatalf("reported with %q, want a view session", coord.reportTokens[0])
	}
}
