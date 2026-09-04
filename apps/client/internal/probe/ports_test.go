package probe

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
)

// listenOn starts a TCP listener on host:0 and returns its port. The listener
// closes with the test.
func listenOn(t *testing.T, host string) int {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Skipf("cannot listen on %s: %v", host, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split %q: %v", ln.Addr(), err)
	}
	port, _ := strconv.Atoi(portStr)
	return port
}

func findPort(rows []PortInfo, port int) (PortInfo, bool) {
	for _, r := range rows {
		if r.Port == port {
			return r, true
		}
	}
	return PortInfo{}, false
}

// The distinction this whole feature rests on: a service bound to 0.0.0.0 is
// reachable at the machine's mesh address, one bound to 127.0.0.1 is not —
// even though BOTH look "listening" to a loopback dial.
func TestPortsSeparatesLoopbackOnlyFromMeshReachable(t *testing.T) {
	// A locally-assigned non-loopback address stands in for the overlay: the
	// kernel treats it the same way (connection stays on this host, but a
	// loopback-only listener still refuses it).
	overlay := localNonLoopbackIPv4(t)

	anyPort := listenOn(t, "0.0.0.0")
	loopPort := listenOn(t, "127.0.0.1")
	t.Setenv("CALABI_PROBE_PORTS", strconv.Itoa(anyPort)+","+strconv.Itoa(loopPort))

	rows := Ports(context.Background(), overlay)

	wide, ok := findPort(rows, anyPort)
	if !ok {
		t.Fatalf("0.0.0.0 listener on %d was not detected", anyPort)
	}
	if !wide.Listening || !wide.MeshProbed || !wide.MeshReachable {
		t.Errorf("0.0.0.0 listener: %+v, want listening + probed + reachable", wide)
	}

	loop, ok := findPort(rows, loopPort)
	if !ok {
		t.Fatalf("127.0.0.1 listener on %d was not detected", loopPort)
	}
	if !loop.Listening {
		t.Errorf("loopback listener should still be reported as listening: %+v", loop)
	}
	if !loop.MeshProbed {
		t.Errorf("loopback listener should have been probed: %+v", loop)
	}
	if loop.MeshReachable {
		t.Error("a 127.0.0.1-only listener must NOT be reported as mesh-reachable — " +
			"declaring it would authorize traffic to an endpoint that always refuses")
	}
}

// No overlay (this machine isn't on the mesh) must read as "not checked", never
// as "not reachable". Two booleans exist precisely to keep those apart.
func TestPortsWithoutOverlayDoesNotClaimUnreachable(t *testing.T) {
	port := listenOn(t, "127.0.0.1")
	t.Setenv("CALABI_PROBE_PORTS", strconv.Itoa(port))

	rows := Ports(context.Background(), "")
	got, ok := findPort(rows, port)
	if !ok {
		t.Fatalf("listener on %d was not detected", port)
	}
	if got.MeshProbed {
		t.Errorf("MeshProbed = true without an overlay address: %+v", got)
	}
	if got.MeshReachable {
		t.Errorf("MeshReachable must stay false when nothing was probed: %+v", got)
	}
}

// localNonLoopbackIPv4 finds an address assigned to this host that isn't
// loopback — the property that makes it behave like the overlay address for
// this test. Skips when the machine has none (CI sandboxes sometimes don't).
func localNonLoopbackIPv4(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("interface addrs: %v", err)
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}
		ip4 := ipnet.IP.To4()
		if ip4 == nil || strings.HasPrefix(ip4.String(), "169.254.") {
			continue
		}
		return ip4.String()
	}
	t.Skip("no non-loopback IPv4 address on this host")
	return ""
}
