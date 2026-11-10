package mesh

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Real WireGuard IP payload, with a UDP/IPv4 header and optional UDP checksum omitted.
func assistDatagram(src, dst netip.Addr, msg string) []byte {
	p := make([]byte, 28+len(msg))
	p[0], p[8], p[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	copy(p[12:16], src.AsSlice())
	copy(p[16:20], dst.AsSlice())
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i:]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(p[10:], ^uint16(sum))
	binary.BigEndian.PutUint16(p[20:], 41111)
	binary.BigEndian.PutUint16(p[22:], 41111)
	binary.BigEndian.PutUint16(p[24:], uint16(len(p)-20))
	copy(p[28:], msg)
	return p
}

// CALABI_ASSIST_P0_FIXTURE is the compiled tools/assist-p0/mesh-fixture.cpp binary.
func TestAssistP0Mesh(t *testing.T) {
	exe := os.Getenv("CALABI_ASSIST_P0_FIXTURE")
	if exe == "" {
		t.Skip("requires native P0 fixture")
	}
	for _, path := range []string{PathDirect, PathRelay} {
		t.Run(path, func(t *testing.T) {
			p := assistPair(t, path)
			type counts struct{ direct, relay uint64 }
			count := func(i int) counts {
				b := p.devices[i].bind
				return counts{b.txDirect.Load(), b.txRelay.Load()}
			}
			base := [2]counts{count(0), count(1)}
			cross := func(from int, msg string) string {
				t.Helper()
				to := 1 - from
				packet := assistDatagram(p.addresses[from], p.addresses[to], msg)
				timer := time.NewTimer(5 * time.Second)
				defer timer.Stop()
				select {
				case p.channels[from].Outbound <- packet:
				case <-timer.C:
					t.Fatal("TUN send stalled")
				}
				select {
				case received := <-p.channels[to].Inbound:
					if !bytes.Equal(received, packet) {
						t.Fatal("datagram changed or misrouted")
					}
					return string(received[28:])
				case <-timer.C:
					t.Fatalf("%s: missing packet %q", path, msg)
				}
				return ""
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, exe)
			in, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			out, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				in.Close()
				if err := cmd.Wait(); err != nil {
					t.Error(err)
				}
			}()
			lines := bufio.NewScanner(out)
			ask := func(prefix, msg string) string {
				t.Helper()
				if _, err := fmt.Fprintln(in, prefix, msg); err != nil {
					t.Fatal(err)
				}
				if !lines.Scan() {
					t.Fatalf("fixture stopped: %v", lines.Err())
				}
				return lines.Text()
			}
			var pairs uint64
			remote := func(msg string) string {
				pairs++
				return cross(1, ask("wire", cross(0, msg)))
			}
			check := func(msg, want string) {
				t.Helper()
				if got := remote(msg); got != want {
					t.Fatalf("%q: got %q, want %q", msg, got, want)
				}
			}
			local := func(action string) {
				t.Helper()
				if ask("local", action) != "ok" {
					t.Fatal(action)
				}
			}
			check("frame", "denied")
			check("local accept", "denied")
			check("frame", "denied")
			local("accept")
			check("frame", "rgb:2aae61")
			check("key 1 1", "denied")
			local("allow")
			grant := remote("status")
			if !strings.HasPrefix(grant, "control ") {
				t.Fatal(grant)
			}
			key := "key " + strings.TrimPrefix(grant, "control ")
			check(key, "applied")
			local("revoke")
			check(key, "denied")
			check("frame", "rgb:2973d4")
			local("reconnect")
			check("frame", "denied")
			check(key, "denied")
			local("accept")
			local("allow")
			check(key, "denied")
			check("key "+strings.TrimPrefix(remote("status"), "control "), "applied")
			if live := os.Getenv("CALABI_ASSIST_P0_LIVE"); live != "" {
				pairs += assistLivePixels(t, live, path, cross)
			}
			for i := range p.devices {
				c := count(i)
				direct, relay := c.direct-base[i].direct, c.relay-base[i].relay
				t.Logf("node=%d exchanges=%d direct_tx=%d relay_tx=%d", i, pairs, direct, relay)
				if (path == PathDirect && (direct < pairs || relay != 0)) || (path == PathRelay && (relay < pairs || direct != 0)) {
					t.Fatal("unexpected transport counters")
				}
			}
		})
	}
}

// Each live process starts in Pending. Only its local Win32 button enables
// DXGI. Network requests can read a verified pixel but cannot change consent.
func assistLivePixels(t *testing.T, exe, path string, cross func(int, string) string) uint64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "--mesh-"+path)
	// The GPU driver creates its DX shader cache when DXGI starts.
	cmd.Env = append(os.Environ(), "LOCALAPPDATA="+t.TempDir())
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		in.Close()
		if err := cmd.Wait(); err != nil {
			t.Error(err)
		}
	}()
	lines := bufio.NewScanner(out)
	var exchanges uint64
	seen := map[string]bool{}
	for len(seen) < 2 {
		request := cross(0, "frame")
		if _, err := fmt.Fprintln(in, request); err != nil {
			t.Fatal(err)
		}
		if !lines.Scan() {
			t.Fatalf("live probe ended: %v", lines.Err())
		}
		reply := cross(1, lines.Text())
		if exchanges == 0 && reply != "denied" {
			t.Fatal("frame available before consent")
		}
		exchanges++
		switch reply {
		case "rgb:2aae61", "rgb:2973d4":
			seen[reply] = true
		case "denied":
		default:
			t.Fatalf("unexpected live reply %q", reply)
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("live: first frame request denied; received both verified DXGI colors over %s", path)
	return exchanges
}

func assistPair(t *testing.T, path string) *probeBusinessPair {
	t.Helper()
	p := newProbeBusinessPair(t, false)
	t.Cleanup(p.cleanup)
	if path == PathRelay {
		for _, d := range p.devices {
			d.detachDirect()
		}
	}
	for _, d := range p.devices {
		deadline := time.Now().Add(8 * time.Second)
		for {
			peers := d.Snapshot().Peers
			if len(peers) == 1 && peers[0].Path == path {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("path %s did not converge", path)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	// Warm the transport before recording per-direction path counters.
	p.transmit(t)
	return p
}
