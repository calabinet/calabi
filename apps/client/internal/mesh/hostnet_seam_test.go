package mesh

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/calabinet/calabi/apps/client/internal/hostnet"
)

// A phone cannot read the interface table itself (Android 11+ refuses the
// netlink query) and reports it through hostnet instead. Both readers must take
// that answer, and filter it exactly as they filter the OS table.
func TestInterfaceReadersUseTheHostnetLister(t *testing.T) {
	addr := func(s string, bits int) hostnet.Address {
		return hostnet.Address{Addr: netip.MustParseAddr(s), Bits: bits}
	}
	hostnet.SetInterfaceLister(func() ([]hostnet.Interface, error) {
		return []hostnet.Interface{
			{Name: "wlan0", Up: true, Addrs: []hostnet.Address{
				addr("192.168.1.37", 24),
				addr("fe80::1", 64), // link-local: never a subnet or an endpoint
			}},
			{Name: "rmnet0", Up: true, Addrs: []hostnet.Address{
				addr("10.20.30.40", -1), // reported without a mask
			}},
			{Name: "tun0", Up: true, Addrs: []hostnet.Address{addr("100.64.0.5", 32)}},
			{Name: "eth9", Up: false, Addrs: []hostnet.Address{addr("172.16.0.2", 16)}},
			{Name: "lo", Up: true, Loopback: true, Addrs: []hostnet.Address{addr("127.0.0.1", 8)}},
		}, nil
	})
	t.Cleanup(func() { hostnet.SetInterfaceLister(nil) })

	subnets, err := localDirectSubnets("tun0")
	if err != nil {
		t.Fatal(err)
	}
	if want := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}; !reflect.DeepEqual(subnets, want) {
		t.Errorf("localDirectSubnets = %v, want %v (no mask, down, loopback and the tun itself all excluded)", subnets, want)
	}

	eps, err := localEndpoints(41641)
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.AddrPort{
		netip.MustParseAddrPort("192.168.1.37:41641"),
		netip.MustParseAddrPort("10.20.30.40:41641"),
	}
	if !reflect.DeepEqual(eps, want) {
		t.Errorf("localEndpoints = %v, want %v (overlay, link-local, down and loopback excluded)", eps, want)
	}
}

// The direct-path UDP socket carries the tunnel too, and needs the same
// protection as the relay link.
func TestMagicSockOpensItsSocketThroughHostnet(t *testing.T) {
	refused := errors.New("protect refused")
	hostnet.SetSocketHook(func(uintptr) error { return refused })
	t.Cleanup(func() { hostnet.SetSocketHook(nil) })

	disco, err := GenerateDiscoKey()
	if err != nil {
		t.Fatal(err)
	}
	ms, err := newMagicSock(disco, nil)
	if err == nil {
		ms.Close()
	}
	if !errors.Is(err, refused) {
		t.Fatalf("newMagicSock err = %v, want the socket hook's refusal (was the socket opened without hostnet?)", err)
	}
}
