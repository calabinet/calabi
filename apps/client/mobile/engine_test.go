package mobile

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/calabinet/calabi/apps/client/internal/creds"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
)

// useMemoryTUNs makes every descriptor the platform returns open as an
// in-memory tun, since a test has no VPN to establish.
func useMemoryTUNs(t *testing.T) {
	t.Helper()
	prev := openTUN
	openTUN = func(int) (tun.Device, error) { return tuntest.NewChannelTUN().TUN(), nil }
	t.Cleanup(func() { openTUN = prev })
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func meshState(t *testing.T, c *Core) map[string]any {
	t.Helper()
	_, st := call(t, c, "GET", "/v1/mesh", "")
	return st
}

// The whole path a phone takes: signed in, Connect, ask the control plane where
// the meshnet is, register with the coordinator as this user, and establish the
// VPN with the address it assigned — then report the peers it can reach.
func TestConnectJoinsTheMeshnetAndEstablishesTheVPN(t *testing.T) {
	useMemoryTUNs(t)
	peerKey, err := meshproto.ParseNodeKey(testNodeKey(2))
	if err != nil {
		t.Fatal(err)
	}
	coord, coordAddr := startFakeCoord(t, &meshpb.NetMap{
		Self: &meshpb.Peer{NodeId: 11, OverlayAddr: "100.64.0.7"},
		Peers: []*meshpb.Peer{{
			NodeId: 12, NodeKey: peerKey.String(), OverlayAddr: "100.64.0.8",
			AllowedIps: []string{"100.64.0.8/32", "10.99.0.0/24"},
			Name:       "home-server", Os: "linux",
			Services: []*meshpb.PeerService{{Name: "nas", Proto: "tcp", Port: 5000}},
		}},
	})
	bff := &fakeBFF{enrollment: fmt.Sprintf(`{"enabled":true,"coord_addr":%q,"relay_addr":"127.0.0.1:1","org_id":7}`, coordAddr)}
	p := &fakePlatform{}
	c := newTestCore(t, bff, p)

	if err := c.Connect(); err == nil {
		t.Fatal("Connect succeeded before signing in")
	}
	signIn(t, c)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}

	waitFor(t, "the VPN to be established", func() bool { return len(p.settings()) > 0 })
	s := p.settings()[0]
	if len(s.Addresses) != 1 || s.Addresses[0] != "100.64.0.7/32" {
		t.Fatalf("VPN addresses = %v, want the coordinator's 100.64.0.7/32", s.Addresses)
	}
	waitFor(t, "the peer's subnet route (accepted by default on a phone)", func() bool {
		all := p.settings()
		return containsRoute(all[len(all)-1].Routes, "10.99.0.0/24")
	})

	reg := coord.registration()
	if reg.GetAuthKey() != bff.currentAccess() || reg.GetName() != "pixel-8-pro" || reg.GetOs() != runtime.GOOS {
		t.Errorf("registered as auth=%q name=%q os=%q; want the session token, the device name and %q",
			reg.GetAuthKey(), reg.GetName(), reg.GetOs(), runtime.GOOS)
	}

	waitFor(t, "state connected", func() bool { return meshState(t, c)["state"] == stateConnected })
	st := meshState(t, c)
	if st["overlay"] != "100.64.0.7" || st["name"] != "pixel-8-pro" {
		t.Errorf("mesh status = %v", st)
	}
	peers, _ := st["peers"].([]any)
	if len(peers) != 1 {
		t.Fatalf("peers = %v, want the one in the netmap", st["peers"])
	}
	peer := peers[0].(map[string]any)
	svcs, _ := peer["services"].([]any)
	if peer["name"] != "home-server" || peer["os"] != "linux" || len(svcs) != 1 {
		t.Errorf("peer = %v, want its name, OS and service from the netmap", peer)
	}
	if _, state := call(t, c, "GET", "/v1/state", ""); state["connected"] != true {
		t.Errorf("state = %v, want connected", state)
	}

	c.Disconnect()
	if st := meshState(t, c); st["state"] != stateStopped {
		t.Errorf("after Disconnect, mesh state = %v", st["state"])
	}
}

// An org without meshnet access is a state the app shows, not an error loop.
func TestConnectWithoutMeshnetAccessSaysSo(t *testing.T) {
	useMemoryTUNs(t)
	bff := &fakeBFF{enrollment: `{"enabled":false}`}
	c := newTestCore(t, bff, &fakePlatform{})
	signIn(t, c)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "state not_enrolled", func() bool { return meshState(t, c)["state"] == stateNotEnrolled })
}

// The enrollment fetch renews an expired token like every other call, instead
// of reporting the phone signed out.
func TestConnectRenewsAnExpiredTokenForEnrollment(t *testing.T) {
	useMemoryTUNs(t)
	bff := &fakeBFF{enrollment: `{"enabled":false}`}
	c := newTestCore(t, bff, &fakePlatform{})
	signIn(t, c)
	bff.expire()
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "state not_enrolled after renewing", func() bool { return meshState(t, c)["state"] == stateNotEnrolled })
}

// Changing a setting restarts a running session, so the new choice is used.
func TestSettingsRestartTheSession(t *testing.T) {
	useMemoryTUNs(t)
	bff := &fakeBFF{enrollment: `{"enabled":false}`}
	c := newTestCore(t, bff, &fakePlatform{})
	signIn(t, c)
	_ = c.Connect()
	before := c.currentEngine()
	if code, _ := call(t, c, "PUT", "/v1/settings", `{"exit_node":"home-server"}`); code != http.StatusOK {
		t.Fatalf("PUT settings = %d", code)
	}
	after := c.currentEngine()
	if after == nil || after == before {
		t.Fatal("the session was not restarted")
	}
	waitFor(t, "the restarted session to report", func() bool {
		b, _ := json.Marshal(meshState(t, c))
		return meshState(t, c)["state"] == stateNotEnrolled && len(b) > 0
	})
}

// testNodeKey is a valid node key string for byte b.
func testNodeKey(b byte) string {
	var k meshproto.NodeKey
	for i := range k {
		k[i] = b
	}
	return k.String()
}

// On a phone the network going away drops the coordinator stream at once, so
// the platform's network callback arrives when the session is already gone and
// the engine is waiting out its backoff. The callback must end that wait: the
// phone is back on a working network, and the backoff (up to a minute) is no
// longer about anything. Found on a real phone, where every Wi-Fi drop cost
// 5-23s and the doubled backoff had reached a minute.
func TestNetworkChangeCutsTheReconnectBackoffShort(t *testing.T) {
	useMemoryTUNs(t)
	coord, coordAddr := startFakeCoord(t, &meshpb.NetMap{Self: &meshpb.Peer{NodeId: 11, OverlayAddr: "100.64.0.7"}})
	coord.mu.Lock()
	coord.failStreams = 3 // sessions end at once; the waits after them are 1s, 2s, 4s
	coord.mu.Unlock()
	bff := &fakeBFF{enrollment: fmt.Sprintf(`{"enabled":true,"coord_addr":%q,"relay_addr":"127.0.0.1:1"}`, coordAddr)}
	c := newTestCore(t, bff, &fakePlatform{})
	signIn(t, c)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}

	waitFor(t, "three failed sessions", func() bool { return coord.registered() >= 3 })
	time.Sleep(300 * time.Millisecond) // well inside the 4s wait after the third

	changed := time.Now()
	c.NetworkChanged()
	waitFor(t, "the next registration", func() bool { return coord.registered() >= 4 })
	if d := time.Since(changed); d > 2*time.Second {
		t.Fatalf("reconnected %v after the network change; want it at once, not at the end of the 4s backoff", d.Round(100*time.Millisecond))
	}
}

// Right after a network change the network is often not usable yet, so the
// first attempts fail at once. Those failures must not double the wait: the
// network usually comes back within seconds, and a doubled backoff then keeps
// the phone off it. Measured on a real phone: Wi-Fi was usable 2-4s after being
// switched back on, while the doubling had already reached 4-8s.
func TestRetriesStayFastRightAfterANetworkChange(t *testing.T) {
	useMemoryTUNs(t)
	coord, coordAddr := startFakeCoord(t, &meshpb.NetMap{Self: &meshpb.Peer{NodeId: 11, OverlayAddr: "100.64.0.7"}})
	coord.mu.Lock()
	coord.failStreams = 6
	coord.mu.Unlock()
	bff := &fakeBFF{enrollment: fmt.Sprintf(`{"enabled":true,"coord_addr":%q,"relay_addr":"127.0.0.1:1"}`, coordAddr)}
	c := newTestCore(t, bff, &fakePlatform{})
	signIn(t, c)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the first failed session", func() bool { return coord.registered() >= 1 })

	changed := time.Now()
	c.NetworkChanged()
	// Five more failures follow. At the minimum wait that is about 5s; doubling
	// (1, 2, 4, 8s) would take 15s and time the wait out.
	waitFor(t, "five more attempts", func() bool { return coord.registered() >= 6 })
	if d := time.Since(changed); d > 8*time.Second {
		t.Fatalf("five retries after a network change took %v; want them at the minimum wait", d.Round(100*time.Millisecond))
	}
}

// A connection opened before the VPN existed is not protected from it. Once
// the VPN routes its destination (an exit device routes everything) its packets
// enter the tunnel with the Wi-Fi source address, no peer accepts them, and the
// pooled connection is reused for every later request. Found on a real phone:
// the device list timed out for as long as an exit device was in use. New
// routes must therefore retire the pool, so the next request dials a socket
// the VPN protects.
func TestRequestsAfterTheVPNRoutesChangeUseAFreshConnection(t *testing.T) {
	useMemoryTUNs(t)
	_, coordAddr := startFakeCoord(t, &meshpb.NetMap{Self: &meshpb.Peer{NodeId: 11, OverlayAddr: "100.64.0.7"}})
	bff := &fakeBFF{enrollment: fmt.Sprintf(`{"enabled":true,"coord_addr":%q,"relay_addr":"127.0.0.1:1"}`, coordAddr)}
	p := &fakePlatform{}
	c, conns := newTestCoreCountingConns(t, bff, p)

	signIn(t, c)
	if code, _ := call(t, c, "GET", "/v1/me", ""); code != http.StatusOK {
		t.Fatalf("GET /v1/me = %d", code)
	}
	if n := conns.Load(); n != 1 {
		t.Fatalf("before the VPN: %d connections, want the one keep-alive connection reused", n)
	}

	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the VPN to be established", func() bool { return len(p.settings()) > 0 })
	before := conns.Load()
	if code, _ := call(t, c, "GET", "/v1/me", ""); code != http.StatusOK {
		t.Fatalf("GET /v1/me = %d", code)
	}
	if conns.Load() != before+1 {
		t.Fatal("a request after the VPN's routes changed reused a connection opened before them")
	}
}

// A network change retires the pool too: its connections belong to the network
// that went away.
func TestRequestsAfterANetworkChangeUseAFreshConnection(t *testing.T) {
	c, conns := newTestCoreCountingConns(t, &fakeBFF{enrollment: `{"enabled":false}`}, &fakePlatform{})
	signIn(t, c)
	if n := conns.Load(); n != 1 {
		t.Fatalf("after sign-in: %d connections, want 1", n)
	}
	c.NetworkChanged()
	if code, _ := call(t, c, "GET", "/v1/me", ""); code != http.StatusOK {
		t.Fatalf("GET /v1/me = %d", code)
	}
	if n := conns.Load(); n != 2 {
		t.Fatalf("after a network change: %d connections, want a second one", n)
	}
}

// The org's device list includes this phone, disconnected or not, and the app
// leaves it out by its mesh address. With no session there is no live address,
// so the core has to remember the last one — per organization, since each
// meshnet assigns its own. Found on a real phone: after disconnecting, the
// phone listed itself among its own devices.
func TestMeshStatusRemembersThisPhonesAddressAfterDisconnect(t *testing.T) {
	useMemoryTUNs(t)
	_, coordAddr := startFakeCoord(t, &meshpb.NetMap{Self: &meshpb.Peer{NodeId: 11, OverlayAddr: "100.64.0.7"}})
	bff := &fakeBFF{enrollment: fmt.Sprintf(`{"enabled":true,"coord_addr":%q,"relay_addr":"127.0.0.1:1","org_id":7}`, coordAddr)}
	c := newTestCore(t, bff, &fakePlatform{})
	signIn(t, c)
	if st := meshState(t, c); st["self_overlay"] != nil {
		t.Fatalf("before ever connecting, self_overlay = %v", st["self_overlay"])
	}
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "state connected", func() bool { return meshState(t, c)["state"] == stateConnected })
	c.Disconnect()

	st := meshState(t, c)
	if st["state"] != stateStopped || st["overlay"] != nil {
		t.Fatalf("after Disconnect: state=%v overlay=%v", st["state"], st["overlay"])
	}
	if st["self_overlay"] != "100.64.0.7" {
		t.Fatalf("after Disconnect, self_overlay = %v, want the address the phone had", st["self_overlay"])
	}

	// Another organization's meshnet never assigned this phone that address.
	cfg, _ := creds.Load()
	cfg.ActiveOrgID = 8
	if err := creds.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if st := meshState(t, c); st["self_overlay"] != nil {
		t.Fatalf("in another organization, self_overlay = %v, want none", st["self_overlay"])
	}
}
