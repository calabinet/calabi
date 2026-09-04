package mesh

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// fakeRelayServer is a minimal calabi-derp stand-in: it accepts links, reads the
// ClientInfo frame, and records every packet frame it is asked to forward — just
// enough to see WHICH relay the pool sent a packet through.
type fakeRelayServer struct {
	addr string
	ln   net.Listener
	// pong answers Ping with Pong, i.e. behaves like a real relay. A server with
	// pong=false is a relay that has stopped answering — the half-open link the
	// pool has to notice on its own.
	pong bool

	mu   sync.Mutex
	got  []meshproto.NodeKey
	conn int
	ch   chan meshproto.NodeKey
}

// startFakeRelay accepts links but answers nothing — it is what most of these
// tests want, and what a relay that has gone away looks like from here.
func startFakeRelay(t *testing.T) *fakeRelayServer { return startRelay(t, false) }

// startLiveFakeRelay answers keepalives, like every relay in the real fleet.
func startLiveFakeRelay(t *testing.T) *fakeRelayServer { return startRelay(t, true) }

func startRelay(t *testing.T, pong bool) *fakeRelayServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeRelayServer{addr: ln.Addr().String(), ln: ln, pong: pong, ch: make(chan meshproto.NodeKey, 8)}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conn++
			s.mu.Unlock()
			go s.serve(conn)
		}
	}()
	return s
}

func (s *fakeRelayServer) serve(conn net.Conn) {
	defer conn.Close()
	for {
		typ, payload, err := meshproto.ReadDERPFrame(conn)
		if err != nil {
			return
		}
		if typ == meshproto.DERPFramePing && s.pong {
			_ = meshproto.WriteDERPFrame(conn, meshproto.DERPFramePong, payload)
			continue
		}
		if typ != meshproto.DERPFrameSendPacket {
			continue
		}
		dst, _, err := meshproto.SplitPacket(payload)
		if err != nil {
			continue
		}
		s.mu.Lock()
		s.got = append(s.got, dst)
		s.mu.Unlock()
		select {
		case s.ch <- dst:
		default:
		}
	}
}

func (s *fakeRelayServer) forwarded() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.got)
}

func (s *fakeRelayServer) waitForward(t *testing.T) meshproto.NodeKey {
	t.Helper()
	select {
	case k := <-s.ch:
		return k
	case <-time.After(3 * time.Second):
		t.Fatalf("relay %s never received a packet", s.addr)
		return meshproto.NodeKey{}
	}
}

func (s *fakeRelayServer) links() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn
}

// A packet for a peer homed at another relay is sent through THAT relay — the
// only one the peer is listening on. The link is dialed lazily, so the first
// packet falls back to our home relay and the ones after it go direct to the
// peer's relay.
func TestRelayPoolSendsViaPeerHomeRelay(t *testing.T) {
	home := startFakeRelay(t)
	remote := startFakeRelay(t)
	self := meshproto.NodeKey{1}
	peer := meshproto.NodeKey{2}

	p := newRelayPool(self, [meshproto.KeyLen]byte{}, nil, slog.Default())
	if err := p.DialHome(context.Background(), home.addr); err != nil {
		t.Fatalf("dial home: %v", err)
	}
	defer p.Close()

	// First send to a not-yet-linked relay: goes out over home, dial starts.
	if err := p.Send(remote.addr, peer, []byte("first")); err != nil {
		t.Fatalf("send: %v", err)
	}
	if got := home.waitForward(t); got != peer {
		t.Fatalf("home relay forwarded to %v, want %v", got, peer)
	}

	// Once the link is up, sends take the peer's own relay.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if err := p.Send(remote.addr, peer, []byte("later")); err != nil {
			t.Fatalf("send: %v", err)
		}
		if remote.forwarded() > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the peer's relay never carried a packet")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := remote.waitForward(t); got != peer {
		t.Fatalf("peer relay forwarded to %v, want %v", got, peer)
	}
}

// Reconcile warms a link to each peer's relay and re-homes this node onto the
// relay its own region resolves to — but only once that link is actually up, so
// a node is never left homed on a relay it can't reach.
func TestRelayPoolReconcileWarmsAndReHomes(t *testing.T) {
	boot := startFakeRelay(t)
	newHome := startFakeRelay(t)
	p := newRelayPool(meshproto.NodeKey{1}, [meshproto.KeyLen]byte{}, nil, slog.Default())
	if err := p.DialHome(context.Background(), boot.addr); err != nil {
		t.Fatalf("dial home: %v", err)
	}
	defer p.Close()
	if p.Home() != boot.addr {
		t.Fatalf("home = %q, want the bootstrap relay", p.Home())
	}

	// First Reconcile only starts the dial; the home must not move to a link that
	// isn't up yet.
	p.Reconcile(newHome.addr, []string{newHome.addr})
	deadline := time.Now().Add(3 * time.Second)
	for p.Home() != newHome.addr {
		if time.Now().After(deadline) {
			t.Fatalf("home never switched to %s (addrs=%v)", newHome.addr, p.Addrs())
		}
		p.Reconcile(newHome.addr, nil) // the switch completes once the link is up
		time.Sleep(20 * time.Millisecond)
	}
	if newHome.links() == 0 {
		t.Fatal("the new home relay was never linked")
	}
	// Both links are kept: peers whose netmap still names the old home keep
	// reaching us there.
	if len(p.Addrs()) != 2 {
		t.Fatalf("pool holds %v, want both the old and new home links", p.Addrs())
	}
}

// A relay whose link is unreachable must not take the node's traffic down: the
// send falls back to the home relay, and an address that never dials just stays
// absent.
func TestRelayPoolFallsBackWhenPeerRelayUnreachable(t *testing.T) {
	home := startFakeRelay(t)
	p := newRelayPool(meshproto.NodeKey{1}, [meshproto.KeyLen]byte{}, nil, slog.Default())
	if err := p.DialHome(context.Background(), home.addr); err != nil {
		t.Fatalf("dial home: %v", err)
	}
	defer p.Close()

	peer := meshproto.NodeKey{2}
	// 203.0.113.0/24 (TEST-NET-1) is unrouted: this relay can never link.
	if err := p.Send("203.0.113.1:3340", peer, []byte("pkt")); err != nil {
		t.Fatalf("send should fall back to home, got %v", err)
	}
	if got := home.waitForward(t); got != peer {
		t.Fatalf("home relay forwarded to %v, want %v", got, peer)
	}
}

// After Close the pool refuses sends instead of writing into torn-down links.
func TestRelayPoolCloseStopsSends(t *testing.T) {
	home := startFakeRelay(t)
	p := newRelayPool(meshproto.NodeKey{1}, [meshproto.KeyLen]byte{}, nil, slog.Default())
	if err := p.DialHome(context.Background(), home.addr); err != nil {
		t.Fatalf("dial home: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := p.Send("", meshproto.NodeKey{2}, []byte("pkt")); err == nil {
		t.Fatal("send after Close should fail")
	}
	if len(p.Addrs()) != 0 {
		t.Fatalf("pool still holds %v after Close", p.Addrs())
	}
}

func TestRelayAddrsByRegion(t *testing.T) {
	m := DERPMap{Regions: []DERPRegion{
		{Code: "lax", Nodes: []DERPNode{
			{HostName: "", DERPPort: 3340},                                  // unusable: no host
			{HostName: "derp-lax.example.net", DERPPort: 3340, STUNPort: 1}, // first usable wins
			{HostName: "derp-lax2.example.net", DERPPort: 3340},
		}},
		{Code: "sgp", Nodes: []DERPNode{{HostName: "derp-sgp.example.net", DERPPort: 3341}}},
		{Code: "broken", Nodes: []DERPNode{{HostName: "h"}}}, // no port: nothing to dial
	}}
	got := relayAddrsByRegion(m)
	if got["lax"] != "derp-lax.example.net:3340" {
		t.Fatalf("lax -> %q", got["lax"])
	}
	if got["sgp"] != "derp-sgp.example.net:3341" {
		t.Fatalf("sgp -> %q", got["sgp"])
	}
	if _, ok := got["broken"]; ok {
		t.Fatalf("a region with no dialable relay must be absent, got %q", got["broken"])
	}
}

// The bind sends a peer's relayed traffic through that peer's home relay, and
// falls back to our own home relay for a peer with no resolvable home.
func TestMeshBindRelaysViaPeerHome(t *testing.T) {
	near := meshproto.NodeKey{1}
	far := meshproto.NodeKey{2}
	homeless := meshproto.NodeKey{3}

	relay := &fakeRelay{}
	b := testBind()
	b.attach(relay)
	b.setPeers(WGConfig{
		RelayByRegion: map[string]string{"lax": "derp-lax:3340", "sgp": "derp-sgp:3340"},
		Peers: []WGPeer{
			{PublicKey: near, DERPHome: "lax"},
			{PublicKey: far, DERPHome: "sgp"},
			{PublicKey: homeless, DERPHome: "atlantis"}, // not in the map
		},
	})

	for _, tc := range []struct {
		peer meshproto.NodeKey
		via  string
	}{
		{near, "derp-lax:3340"},
		{far, "derp-sgp:3340"},
		{homeless, ""}, // "" = our own home relay
	} {
		if err := b.Send([][]byte{wgPacket("x")}, &meshEndpoint{b: b, key: tc.peer}); err != nil {
			t.Fatalf("send: %v", err)
		}
		if got := relay.lastVia(); got != tc.via {
			t.Fatalf("peer %v relayed via %q, want %q", tc.peer, got, tc.via)
		}
	}
}

// The datapath links to each distinct relay its peers are homed at — once per
// relay, however many peers share it.
func TestPeerRelayAddrsDeduplicates(t *testing.T) {
	cfg := WGConfig{
		RelayByRegion: map[string]string{"lax": "derp-lax:3340", "sgp": "derp-sgp:3340"},
		Peers: []WGPeer{
			{PublicKey: meshproto.NodeKey{1}, DERPHome: "lax"},
			{PublicKey: meshproto.NodeKey{2}, DERPHome: "lax"},
			{PublicKey: meshproto.NodeKey{3}, DERPHome: "sgp"},
			{PublicKey: meshproto.NodeKey{4}, DERPHome: "nowhere"},
			{PublicKey: meshproto.NodeKey{5}}, // no home at all
		},
	}
	got := peerRelayAddrs(cfg)
	if len(got) != 2 {
		t.Fatalf("peerRelayAddrs = %v, want one entry per distinct relay", got)
	}
}

// BuildWGConfig carries the fleet's region->relay map and this node's own home
// relay through to the datapath.
func TestBuildWGConfigCarriesRelayFleet(t *testing.T) {
	nm := NetMap{
		Self: Peer{DERPHome: "sgp"},
		DERP: DERPMap{Regions: []DERPRegion{
			{Code: "lax", Nodes: []DERPNode{{HostName: "derp-lax.example.net", DERPPort: 3340}}},
			{Code: "sgp", Nodes: []DERPNode{{HostName: "derp-sgp.example.net", DERPPort: 3340}}},
		}},
		Peers: []Peer{{NodeKey: meshproto.NodeKey{1}, DERPHome: "lax"}},
	}
	cfg := BuildWGConfig(nm)
	if cfg.SelfRelay != "derp-sgp.example.net:3340" {
		t.Fatalf("SelfRelay = %q, want this node's home region relay", cfg.SelfRelay)
	}
	if cfg.RelayByRegion["lax"] != "derp-lax.example.net:3340" {
		t.Fatalf("RelayByRegion = %v", cfg.RelayByRegion)
	}
	if len(cfg.Peers) != 1 || cfg.Peers[0].DERPHome != "lax" {
		t.Fatalf("peer home didn't survive: %+v", cfg.Peers)
	}
}
