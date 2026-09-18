package hostnet

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
)

// The hooks are process-wide, so no test here runs in parallel and each one
// removes what it installed.

func TestSocketHookRunsForDialsAndListens(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	// Built BEFORE the hook exists: a long-lived dialer must still honor it.
	early := Dialer()

	var seen atomic.Int32
	SetSocketHook(func(fd uintptr) error {
		seen.Add(1)
		return nil
	})
	t.Cleanup(func() { SetSocketHook(nil) })

	c, err := early.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.Close()
	pc, err := ListenConfig().ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	pc.Close()
	if n := seen.Load(); n != 2 {
		t.Fatalf("hook ran %d times, want 2 (one dial, one listen)", n)
	}
}

func TestSocketHookErrorAbortsTheSocket(t *testing.T) {
	refused := errors.New("not protected")
	SetSocketHook(func(uintptr) error { return refused })
	t.Cleanup(func() { SetSocketHook(nil) })

	_, err := ListenConfig().ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if !errors.Is(err, refused) {
		t.Fatalf("listen err = %v, want it to wrap the hook's error", err)
	}
}

func TestNoHookIsThePlainDefault(t *testing.T) {
	if Resolver() != net.DefaultResolver {
		t.Fatal("Resolver() without an override is not net.DefaultResolver")
	}
	r := &net.Resolver{PreferGo: true}
	SetResolver(r)
	if Resolver() != r {
		t.Fatal("SetResolver did not take effect")
	}
	SetResolver(nil)
	if Resolver() != net.DefaultResolver {
		t.Fatal("SetResolver(nil) did not restore the default")
	}

	got, err := Interfaces()
	if err != nil {
		t.Fatalf("Interfaces: %v", err)
	}
	want, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("Interfaces() = %d interfaces, the OS table has %d", len(got), len(want))
	}
}

func TestInterfaceListerReplacesTheOSTable(t *testing.T) {
	fake := []Interface{{Name: "wlan0", Up: true, Addrs: []Address{{Addr: netip.MustParseAddr("192.0.2.7"), Bits: 24}}}}
	SetInterfaceLister(func() ([]Interface, error) { return fake, nil })
	t.Cleanup(func() { SetInterfaceLister(nil) })

	got, err := Interfaces()
	if err != nil || len(got) != 1 || got[0].Name != "wlan0" {
		t.Fatalf("Interfaces() = %v, %v; want the lister's answer", got, err)
	}
}

func TestOSAddressesKeepsTheMaskMeaning(t *testing.T) {
	got := osAddresses([]net.Addr{
		&net.IPNet{IP: net.ParseIP("192.168.1.37").To4(), Mask: net.CIDRMask(24, 32)},
		&net.IPNet{IP: net.ParseIP("192.168.1.38"), Mask: net.IPMask{0xff, 0x00, 0xff, 0x00}}, // not canonical
		&net.IPAddr{IP: net.ParseIP("203.0.113.9")},
	})
	want := []int{24, 0, -1}
	if len(got) != len(want) {
		t.Fatalf("got %d addresses, want %d: %v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].Bits != w {
			t.Errorf("address %d (%v): Bits = %d, want %d", i, got[i].Addr, got[i].Bits, w)
		}
	}
}
