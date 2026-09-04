package mesh

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"testing"

	"github.com/calabi/calabi/pkg/mesh-proto/stun"
)

func TestStunHostPortFor(t *testing.T) {
	nm := NetMap{
		Self: Peer{DERPHome: "sgp"},
		DERP: DERPMap{Regions: []DERPRegion{
			{Code: "lax", Nodes: []DERPNode{{HostName: "derp-lax.example.net", DERPPort: 3340, STUNPort: 3478}}},
			{Code: "sgp", Nodes: []DERPNode{{HostName: "derp-sgp.example.net", DERPPort: 3340, STUNPort: 3479}}},
		}},
	}
	if hp, ok := stunHostPortFor(nm); !ok || hp != "derp-sgp.example.net:3479" {
		t.Fatalf("got %q ok=%v, want derp-sgp.example.net:3479", hp, ok)
	}
	// No home region set.
	if _, ok := stunHostPortFor(NetMap{DERP: nm.DERP}); ok {
		t.Fatal("no home should yield ok=false")
	}
	// Home region present but its relay advertises no STUN port.
	noStun := NetMap{
		Self: Peer{DERPHome: "lax"},
		DERP: DERPMap{Regions: []DERPRegion{{Code: "lax", Nodes: []DERPNode{{HostName: "h", DERPPort: 3340}}}}},
	}
	if _, ok := stunHostPortFor(noStun); ok {
		t.Fatal("missing STUN port should yield ok=false")
	}
}

func TestResolveSTUNServerLiteral(t *testing.T) {
	ap, ok := resolveSTUNServer(context.Background(), "203.0.113.5:3478")
	if !ok || ap.String() != "203.0.113.5:3478" {
		t.Fatalf("literal: got %s ok=%v", ap, ok)
	}
	for _, bad := range []string{"no-port", "1.2.3.4:0", "1.2.3.4:99999", "host-only:"} {
		if _, ok := resolveSTUNServer(context.Background(), bad); ok {
			t.Errorf("resolveSTUNServer(%q) should fail", bad)
		}
	}
}

// Reflexive over a loopback STUN responder returns this socket's own observed
// address — proving the request goes out the shared socket and the response is
// demultiplexed back to the waiter by transaction id.
func TestMagicSockReflexive(t *testing.T) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := srv.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if tx, ok := stun.IsBindingRequest(buf[:n]); ok {
				resp := stun.BindingResponse(tx, netip.AddrPortFrom(from.Addr().Unmap(), from.Port()))
				_, _ = srv.WriteToUDPAddrPort(resp, from)
			}
		}
	}()

	disco, _ := GenerateDiscoKey()
	ms, err := newMagicSock(disco, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer ms.Close()

	srvAP := srv.LocalAddr().(*net.UDPAddr).AddrPort()
	srvAP = netip.AddrPortFrom(srvAP.Addr().Unmap(), srvAP.Port())
	refl, err := ms.Reflexive(context.Background(), srvAP)
	if err != nil {
		t.Fatalf("reflexive: %v", err)
	}
	if refl.Port() != ms.LocalPort() {
		t.Fatalf("reflexive port = %d, want the socket's own port %d", refl.Port(), ms.LocalPort())
	}
	if !refl.Addr().IsLoopback() {
		t.Fatalf("reflexive addr = %s, want loopback", refl.Addr())
	}
}

// A probe to a black hole (no responder) times out rather than hanging.
func TestMagicSockReflexiveTimeout(t *testing.T) {
	disco, _ := GenerateDiscoKey()
	ms, err := newMagicSock(disco, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer ms.Close()
	// TEST-NET-1 (203.0.113.0/24) is unrouted; the probe must time out.
	ctx, cancel := context.WithTimeout(context.Background(), 500*1000*1000) // 500ms
	defer cancel()
	if _, err := ms.Reflexive(ctx, netip.MustParseAddrPort("203.0.113.1:3478")); err == nil {
		t.Fatal("expected a timeout error probing a black hole")
	}
}
