// Package hostnet is how the client's own sockets reach the network, and how it
// learns which addresses this device has.
//
// On a desktop both are the operating system's defaults and nothing here
// changes them: every hook starts empty, and an empty hook is the plain
// net.Dialer / net.ListenConfig / net.DefaultResolver / net.Interfaces the code
// used before this package existed. A phone needs them overridden:
//
//   - Android sends the device's traffic, this app's included, into the VPN the
//     app is running. A socket that CARRIES the tunnel — the relay link, the
//     direct-path UDP socket, the coordinator stream — has to be excluded with
//     VpnService.protect, or its packets loop back into the tunnel they carry.
//   - Android 11+ refuses the netlink query net.Interfaces is built on, and a
//     Go binary there has no /etc/resolv.conf to find a DNS server in. Only the
//     platform can answer either question.
//
// The hooks are process-wide because what they describe is: one device, one
// VPN. Install them before the first socket is opened.
package hostnet

import (
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
)

// SocketHook runs on every socket opened through Dialer or ListenConfig, after
// it is created and before it connects or binds. An error aborts that socket.
type SocketHook func(fd uintptr) error

var socketHook atomic.Pointer[SocketHook]

// SetSocketHook installs h for every socket opened from now on (nil removes it).
func SetSocketHook(h SocketHook) {
	if h == nil {
		socketHook.Store(nil)
		return
	}
	socketHook.Store(&h)
}

// HasSocketHook reports whether a socket hook is installed. For a caller whose
// library dials on its own unless handed a dialer, and who would lose that
// library's own behavior (a proxy, say) by always handing it one.
func HasSocketHook() bool { return socketHook.Load() != nil }

// control is the net.Dialer / net.ListenConfig Control func. It reads the hook
// when the socket is created, not when the dialer was built, so a long-lived
// dialer still honors a hook installed after it.
func control(_, _ string, c syscall.RawConn) error {
	h := socketHook.Load()
	if h == nil {
		return nil
	}
	var hookErr error
	if err := c.Control(func(fd uintptr) { hookErr = (*h)(fd) }); err != nil {
		return err
	}
	if hookErr != nil {
		return fmt.Errorf("hostnet: socket hook: %w", hookErr)
	}
	return nil
}

// Dialer returns a dialer whose sockets pass through the socket hook. Set its
// other fields (Timeout, KeepAlive, ...) as with a zero net.Dialer.
func Dialer() *net.Dialer { return &net.Dialer{Control: control} }

// ListenConfig returns a listen config whose sockets pass through the socket hook.
func ListenConfig() *net.ListenConfig { return &net.ListenConfig{Control: control} }

var resolver atomic.Pointer[net.Resolver]

// SetResolver replaces the resolver Resolver returns (nil restores the default).
func SetResolver(r *net.Resolver) { resolver.Store(r) }

// Resolver is the resolver for names the client itself looks up: relays, STUN
// servers, the coordinator.
func Resolver() *net.Resolver {
	if r := resolver.Load(); r != nil {
		return r
	}
	return net.DefaultResolver
}

// Interface is one network interface as the client needs to see it.
type Interface struct {
	Name     string
	Up       bool
	Loopback bool
	Addrs    []Address
}

// Address is an interface address and the length of its on-link prefix.
type Address struct {
	Addr netip.Addr
	// Bits is the on-link prefix length: 24 for 192.168.1.37/24. It is -1 when
	// the address was reported without a mask, and 0 when the mask was not in
	// canonical form — neither describes a subnet.
	Bits int
}

// InterfaceLister reports the device's interfaces.
type InterfaceLister func() ([]Interface, error)

var lister atomic.Pointer[InterfaceLister]

// SetInterfaceLister replaces the OS interface table with fn (nil restores it).
func SetInterfaceLister(fn InterfaceLister) {
	if fn == nil {
		lister.Store(nil)
		return
	}
	lister.Store(&fn)
}

// Interfaces lists the device's interfaces: from the installed lister, else the
// OS interface table. An interface whose addresses cannot be read is listed
// without addresses rather than failing the whole call.
func Interfaces() ([]Interface, error) {
	if fn := lister.Load(); fn != nil {
		return (*fn)()
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]Interface, 0, len(ifaces))
	for _, ifc := range ifaces {
		it := Interface{
			Name:     ifc.Name,
			Up:       ifc.Flags&net.FlagUp != 0,
			Loopback: ifc.Flags&net.FlagLoopback != 0,
		}
		if as, err := ifc.Addrs(); err == nil {
			it.Addrs = osAddresses(as)
		}
		out = append(out, it)
	}
	return out, nil
}

// osAddresses converts the addresses net.Interface.Addrs returns.
func osAddresses(as []net.Addr) []Address {
	out := make([]Address, 0, len(as))
	for _, a := range as {
		switch v := a.(type) {
		case *net.IPNet:
			if ip, ok := netip.AddrFromSlice(v.IP); ok {
				ones, _ := v.Mask.Size()
				out = append(out, Address{Addr: ip, Bits: ones})
			}
		case *net.IPAddr:
			if ip, ok := netip.AddrFromSlice(v.IP); ok {
				out = append(out, Address{Addr: ip, Bits: -1})
			}
		}
	}
	return out
}
