package probe

import (
	"context"
	"net/netip"
	"testing"
)

// The kernel's hex form is the trap this parser exists to get right: an IPv4
// address is stored little-endian, so 127.0.0.1 reads as "0100007F", and the
// wildcard bind is all zeros. Getting the byte order wrong would mislabel every
// address — the exact fact the feature is meant to surface.
func TestParseHexAddrV4(t *testing.T) {
	cases := []struct {
		cell string
		ip   string
		port int
	}{
		{"0100007F:1F90", "127.0.0.1", 8080},   // loopback, 8080
		{"00000000:0016", "0.0.0.0", 22},       // wildcard, ssh
		{"0101A8C0:0050", "192.168.1.1", 80},   // a specific LAN IP
	}
	for _, c := range cases {
		ip, port, ok := parseHexAddr(c.cell, false)
		if !ok {
			t.Errorf("%s: parse failed", c.cell)
			continue
		}
		if ip.String() != c.ip || port != c.port {
			t.Errorf("%s -> %s:%d, want %s:%d", c.cell, ip, port, c.ip, c.port)
		}
	}
}

func TestParseHexAddrV6(t *testing.T) {
	// ::1 (loopback): 15 zero bytes then 0x01, so the last 32-bit word is
	// little-endian "01000000".
	ip, port, ok := parseHexAddr("00000000000000000000000001000000:0050", true)
	if !ok || ip.String() != "::1" || port != 80 {
		t.Errorf("::1 -> %s:%d (ok=%v), want ::1:80", ip, port, ok)
	}
	// :: (wildcard) is all zeros.
	ip, _, ok = parseHexAddr("00000000000000000000000000000000:1F90", true)
	if !ok || !ip.IsUnspecified() {
		t.Errorf(":: -> %s (ok=%v), want the unspecified address", ip, ok)
	}
}

// A real /proc/net/tcp dump: a header line, a LISTEN socket, and an established
// one that must be ignored — only listeners are declarable.
func TestParseProcNetTCP(t *testing.T) {
	sample := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000\n" +
		"   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000\n" +
		"   2: 0100007F:1F90 0100007F:C1B4 01 00000000:00000000 00:00000000 00000000  1000        0 12347 1 0000000000000000\n"
	ls, err := parseProcNetTCP([]byte(sample), false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(ls) != 2 {
		t.Fatalf("got %d listeners, want 2 (the established socket must be dropped)", len(ls))
	}
	if ls[0].ip.String() != "127.0.0.1" || ls[0].port != 8080 {
		t.Errorf("listener[0] = %s:%d, want 127.0.0.1:8080", ls[0].ip, ls[0].port)
	}
	if !ls[1].ip.IsUnspecified() || ls[1].port != 22 {
		t.Errorf("listener[1] = %s:%d, want 0.0.0.0:22", ls[1].ip, ls[1].port)
	}
}

// netstat's local-address form uses "." before the port and "*" for wildcard;
// non-LISTEN lines and the header must be ignored.
func TestParseNetstat(t *testing.T) {
	sample := "Active Internet connections (including servers)\n" +
		"Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)\n" +
		"tcp4       0      0  127.0.0.1.5432         *.*                    LISTEN\n" +
		"tcp6       0      0  ::1.5432               *.*                    LISTEN\n" +
		"tcp4       0      0  *.8080                 *.*                    LISTEN\n" +
		"tcp4       0      0  192.168.1.5.52344      93.184.216.34.443      ESTABLISHED\n"
	ls, err := parseNetstat([]byte(sample))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(ls) != 3 {
		t.Fatalf("got %d listeners, want 3", len(ls))
	}
	if ls[0].ip.String() != "127.0.0.1" || ls[0].port != 5432 {
		t.Errorf("listener[0] = %s:%d, want 127.0.0.1:5432", ls[0].ip, ls[0].port)
	}
	if ls[2].ip.String() != "0.0.0.0" || ls[2].port != 8080 {
		t.Errorf("listener[2] = %s:%d, want 0.0.0.0:8080", ls[2].ip, ls[2].port)
	}
}

// scanFrom must surface the bind address and, crucially, tell a wildcard bind
// (reachable at the overlay) from a loopback-only one (listening but no peer can
// reach it) — decided by a real dial, exactly as the dial path decides it.
func TestScanFromSeparatesReachableFromLoopbackOnly(t *testing.T) {
	overlay := localNonLoopbackIPv4(t)

	widePort := listenOn(t, "0.0.0.0")
	loopPort := listenOn(t, "127.0.0.1")

	socks := []listener{
		{ip: netip.IPv4Unspecified(), port: widePort},
		{ip: netip.MustParseAddr("127.0.0.1"), port: loopPort},
	}
	rows := scanFrom(context.Background(), socks, overlay)

	wide, ok := findPort(rows, widePort)
	if !ok {
		t.Fatalf("wildcard port %d missing from scan", widePort)
	}
	if wide.Source != "enumerated" || len(wide.BindAddrs) == 0 || wide.BindAddrs[0] != "0.0.0.0" {
		t.Errorf("wildcard row = %+v, want source=enumerated + bind 0.0.0.0", wide)
	}
	if !wide.MeshProbed || !wide.MeshReachable {
		t.Errorf("wildcard row = %+v, want probed + reachable", wide)
	}

	loop, ok := findPort(rows, loopPort)
	if !ok {
		t.Fatalf("loopback port %d missing from scan", loopPort)
	}
	if loop.BindAddrs[0] != "127.0.0.1" {
		t.Errorf("loopback bind = %v, want 127.0.0.1", loop.BindAddrs)
	}
	if !loop.MeshProbed {
		t.Errorf("loopback row should have been probed: %+v", loop)
	}
	if loop.MeshReachable {
		t.Error("a 127.0.0.1-only listener must not be reported mesh-reachable")
	}
}

// Without an overlay (not on the mesh), reachability is left unprobed — never
// reported as false, same contract the two booleans carry everywhere else.
func TestScanFromWithoutOverlayLeavesReachabilityUnprobed(t *testing.T) {
	port := listenOn(t, "0.0.0.0")
	rows := scanFrom(context.Background(), []listener{{ip: netip.IPv4Unspecified(), port: port}}, "")
	got, ok := findPort(rows, port)
	if !ok {
		t.Fatalf("port %d missing", port)
	}
	if got.MeshProbed || got.MeshReachable {
		t.Errorf("row = %+v, want neither probed nor reachable without an overlay", got)
	}
}

// The same port bound on several addresses collapses to one row that lists each
// address once.
func TestScanFromDedupsBindsPerPort(t *testing.T) {
	socks := []listener{
		{ip: netip.MustParseAddr("127.0.0.1"), port: 9000},
		{ip: netip.MustParseAddr("192.168.1.10"), port: 9000},
		{ip: netip.MustParseAddr("127.0.0.1"), port: 9000}, // duplicate
	}
	rows := scanFrom(context.Background(), socks, "")
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if len(rows[0].BindAddrs) != 2 {
		t.Errorf("binds = %v, want two distinct addresses", rows[0].BindAddrs)
	}
}

// Rows come back ascending by port so the table order is stable across scans.
func TestScanFromSortsByPort(t *testing.T) {
	socks := []listener{
		{ip: netip.IPv4Unspecified(), port: 8080},
		{ip: netip.IPv4Unspecified(), port: 22},
		{ip: netip.IPv4Unspecified(), port: 443},
	}
	rows := scanFrom(context.Background(), socks, "")
	want := []int{22, 443, 8080}
	for i, w := range want {
		if rows[i].Port != w {
			t.Errorf("rows[%d].Port = %d, want %d", i, rows[i].Port, w)
		}
	}
}

// Whatever the live platform reports, listenerSockets must not hand back
// sockets with an obviously bogus port — a cheap guard that the row layout
// (and the state filtering) on the real machine isn't off by a field.
func TestLivePortsAreInRange(t *testing.T) {
	socks, err := listenerSockets()
	if err != nil {
		t.Skipf("enumeration unavailable here: %v", err)
	}
	for _, s := range socks {
		if s.port < 1 || s.port > 65535 {
			t.Errorf("listener %s has an out-of-range port %d", s.ip, s.port)
		}
		if !s.ip.IsValid() {
			t.Errorf("listener on port %d has an invalid bind address", s.port)
		}
	}
}
