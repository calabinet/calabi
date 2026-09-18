package mesh

import (
	"io"
	"log/slog"
	"net/netip"
	"reflect"
	"sync"
	"testing"

	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/calabi/calabi/apps/client/internal/hostnet"
	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// recordingRouting is a platform Routing that remembers what it was asked to do.
type recordingRouting struct {
	mu       sync.Mutex
	links    []netip.Addr
	added    []netip.Prefix
	deleted  []netip.Prefix
	exits    int
	cleanups int
	// bypass is what OwnSocketsBypassTunnel answers: true like a phone.
	bypass bool
}

func (r *recordingRouting) OwnSocketsBypassTunnel() bool { return r.bypass }

func (r *recordingRouting) ConfigureLink(o netip.Addr) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.links = append(r.links, o)
	return nil
}

func (r *recordingRouting) AddSubnetRoutes(p []netip.Prefix) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.added = append(r.added, p...)
	return nil
}

func (r *recordingRouting) DelSubnetRoutes(p []netip.Prefix) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deleted = append(r.deleted, p...)
	return nil
}

func (r *recordingRouting) EnableExitRoutes([]netip.Addr, []netip.Prefix) (func(), error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.exits++
	return func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.cleanups++
	}, nil
}

// On a phone the platform opens the tun and owns the routes. Every routing
// decision the datapath makes must reach the platform's Routing — none may fall
// through to this process's own OS calls, which a phone app cannot make.
func TestDatapathOnPlatformTUNRoutesThroughThePlatform(t *testing.T) {
	// No local networks, so no advertised prefix loses to one.
	hostnet.SetInterfaceLister(func() ([]hostnet.Interface, error) { return nil, nil })
	t.Cleanup(func() { hostnet.SetInterfaceLister(nil) })

	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	peerPriv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	peer := peerPriv.Public()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rt := &recordingRouting{}
	// Nothing listens on port 1: the relay stays down, which the datapath tolerates.
	const relay = "127.0.0.1:1"
	d, err := NewWGDatapathOnTUN(tuntest.NewChannelTUN().TUN(), rt, priv, relay, logger)
	if err != nil {
		t.Fatalf("NewWGDatapathOnTUN: %v", err)
	}
	defer d.Close()

	overlay := netip.MustParseAddr("100.64.0.9")
	subnet := netip.MustParsePrefix("10.99.0.0/16")
	withExit := WGConfig{
		OverlayAddr: overlay,
		SelfRelay:   relay,
		ExitNode:    peer,
		Peers: []WGPeer{{
			PublicKey: peer,
			AllowedIPs: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.10/32"),
				subnet,
				netip.MustParsePrefix("0.0.0.0/0"),
			},
		}},
	}
	if err := d.SetConfig(withExit); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	rt.mu.Lock()
	if !reflect.DeepEqual(rt.links, []netip.Addr{overlay}) {
		t.Errorf("ConfigureLink calls = %v, want [%v]", rt.links, overlay)
	}
	if !reflect.DeepEqual(rt.added, []netip.Prefix{subnet}) {
		t.Errorf("AddSubnetRoutes got %v, want [%v]", rt.added, subnet)
	}
	if rt.exits != 1 {
		t.Errorf("EnableExitRoutes calls = %d, want 1", rt.exits)
	}
	rt.mu.Unlock()

	// The peer stops advertising the subnet and the exit node is deselected: both
	// must be withdrawn through the platform too.
	without := withExit
	without.ExitNode = meshproto.NodeKey{}
	without.Peers = []WGPeer{{PublicKey: peer, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.10/32")}}}
	if err := d.SetConfig(without); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if len(rt.links) != 1 {
		t.Errorf("ConfigureLink calls = %d after an unchanged overlay, want still 1", len(rt.links))
	}
	if !reflect.DeepEqual(rt.deleted, []netip.Prefix{subnet}) {
		t.Errorf("DelSubnetRoutes got %v, want [%v]", rt.deleted, subnet)
	}
	if rt.cleanups != 1 {
		t.Errorf("exit-route cleanups = %d, want 1", rt.cleanups)
	}
}

func TestDatapathOnPlatformTUNRequiresRouting(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewWGDatapathOnTUN(tuntest.NewChannelTUN().TUN(), nil, priv, "127.0.0.1:1", slog.Default()); err == nil {
		t.Fatal("NewWGDatapathOnTUN with no Routing succeeded; it would fall back to OS calls a phone cannot make")
	}
}

// An exit device's full tunnel pauses direct paths only where it would capture
// the direct-path socket. A phone's sockets are protected from the VPN, so there
// the peers stay direct; before this, choosing an exit sent every peer on the
// same Wi-Fi through a relay (measured on a real phone: 12ms direct, 183ms relayed).
func TestExitKeepsDirectPathsOnlyWhereOwnSocketsBypassTheTunnel(t *testing.T) {
	hostnet.SetInterfaceLister(func() ([]hostnet.Interface, error) { return nil, nil })
	t.Cleanup(func() { hostnet.SetInterfaceLister(nil) })

	for _, tc := range []struct {
		name       string
		bypass     bool
		wantDirect bool
	}{
		{"phone", true, true},
		{"desktop", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			priv, _ := GenerateKey()
			peerPriv, _ := GenerateKey()
			peer := peerPriv.Public()
			rt := &recordingRouting{bypass: tc.bypass}
			const relay = "127.0.0.1:1"
			d, err := NewWGDatapathOnTUN(tuntest.NewChannelTUN().TUN(), rt, priv, relay, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			ms, err := newMagicSock(DiscoPrivateKey{}, nil)
			if err != nil {
				t.Skipf("no UDP socket available: %v", err)
			}
			defer ms.Close()
			d.attachDirect(ms, nil)

			if err := d.SetConfig(WGConfig{
				OverlayAddr: netip.MustParseAddr("100.64.0.9"),
				SelfRelay:   relay,
				ExitNode:    peer,
				Peers: []WGPeer{{PublicKey: peer, AllowedIPs: []netip.Prefix{
					netip.MustParsePrefix("100.64.0.10/32"), netip.MustParsePrefix("0.0.0.0/0"),
				}}},
			}); err != nil {
				t.Fatal(err)
			}
			if rt.exits != 1 {
				t.Fatalf("exit routes enabled %d times, want 1", rt.exits)
			}
			ep := &meshEndpoint{b: d.bind, key: peer, direct: netip.MustParseAddrPort("192.168.1.5:41641")}
			if _, _, _, direct := d.bind.directTarget(ep); direct != tc.wantDirect {
				t.Fatalf("with an exit device in use, direct send = %v, want %v", direct, tc.wantDirect)
			}
		})
	}
}
