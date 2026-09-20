package main

import (
	"encoding/binary"
	"net"
	"sort"
	"testing"
	"time"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// A diagnostic that reports the wrong number is worse than no diagnostic, so the
// measurement itself gets pinned here against a server whose behaviour is known
// exactly. The fake speaks only the two frames this test drives — ClientInfo in,
// Ping echoed as Pong — which is the whole contract relaytest relies on.
func startEchoRelay(t *testing.T, onPing func(payload []byte) (reply bool)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if typ, _, err := meshproto.ReadDERPFrame(conn); err != nil || typ != meshproto.DERPFrameClientInfo {
					return
				}
				for {
					typ, payload, err := meshproto.ReadDERPFrame(conn)
					if err != nil {
						return
					}
					if typ != meshproto.DERPFramePing {
						continue
					}
					if onPing != nil && !onPing(payload) {
						continue
					}
					if err := meshproto.WriteDERPFrame(conn, meshproto.DERPFramePong, payload); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// The straightforward case: a relay that echoes everything is reported as
// lossless, and the RTTs are real durations rather than the zero a broken
// timestamp round-trip would produce.
func TestRelayLegReportsALosslessLinkAsLossless(t *testing.T) {
	addr := startEchoRelay(t, nil)
	res, err := driveRelayLeg(relayTestConfig{addr: addr, seconds: 1, size: 256, rate: 8})
	if err != nil {
		t.Fatalf("drive: %v", err)
	}
	if res.sent == 0 {
		t.Fatal("sent nothing")
	}
	if res.echoed != res.sent {
		t.Errorf("echoed %d of %d frames on a lossless echo server", res.echoed, res.sent)
	}
	if len(res.rtts) != int(res.echoed) {
		t.Errorf("recorded %d RTTs for %d echoes", len(res.rtts), res.echoed)
	}
	// Not asserting a POSITIVE RTT here: a loopback round trip can land inside the
	// host clock's granularity and legitimately measure zero (it does on Windows).
	// Whether the RTT tracks reality is a separate question, and the test below
	// answers it with a delay big enough that no clock can miss it.
	for _, d := range res.rtts {
		if d < 0 || d > 10*time.Second {
			t.Fatalf("implausible RTT %v", d)
		}
	}
	if res.linkDiedEarly {
		t.Error("reported the link as dying early against a healthy server")
	}
}

// The RTT has to be a measurement, not a decoration. A relay held 25 ms per
// frame must show up as roughly 25 ms — anything that merely returns a
// non-negative duration would pass the check above while reporting nothing.
//
// The offered rate stays well under the delayed server's echo capacity
// (40 frames/s at 25 ms), so what is measured is the delay itself and not a
// queue built by offering more than the far side can return.
func TestRelayLegMeasuresRoundTripTime(t *testing.T) {
	const held = 25 * time.Millisecond
	addr := startEchoRelay(t, func([]byte) bool {
		time.Sleep(held)
		return true
	})
	// 20 frames/s of 256 B = 0.041 Mbit/s.
	res, err := driveRelayLeg(relayTestConfig{addr: addr, seconds: 2, size: 256, rate: 0.041})
	if err != nil {
		t.Fatalf("drive: %v", err)
	}
	if len(res.rtts) < 5 {
		t.Fatalf("only %d RTT samples; too few to judge", len(res.rtts))
	}
	sort.Slice(res.rtts, func(i, j int) bool { return res.rtts[i] < res.rtts[j] })
	p50 := res.rtts[len(res.rtts)/2]
	if p50 < held || p50 > held+150*time.Millisecond {
		t.Errorf("p50 RTT %v against a relay holding each frame for %v", p50, held)
	}
}

// Loss has to show up as loss. Without this the tool could report every link as
// perfect and nobody would notice until it was being trusted.
func TestRelayLegCountsWhatDoesNotComeBack(t *testing.T) {
	var n int
	addr := startEchoRelay(t, func([]byte) bool {
		n++
		return n%2 == 0 // swallow every other ping
	})
	res, err := driveRelayLeg(relayTestConfig{addr: addr, seconds: 1, size: 256, rate: 8})
	if err != nil {
		t.Fatalf("drive: %v", err)
	}
	if res.sent < 4 {
		t.Fatalf("only sent %d frames; too few to judge", res.sent)
	}
	// Half, with a wide margin for where the run happens to stop.
	if res.echoed == 0 || res.echoed >= res.sent {
		t.Errorf("echoed %d of %d, want roughly half", res.echoed, res.sent)
	}
}

// The pacing has to be honest: --rate is what the operator will compare against
// iperf3, so an offered rate that silently ignores the flag makes the comparison
// meaningless.
func TestRelayLegHonoursTheOfferedRate(t *testing.T) {
	addr := startEchoRelay(t, nil)
	const size, mbps = 1000, 4.0
	res, err := driveRelayLeg(relayTestConfig{addr: addr, seconds: 2, size: size, rate: mbps})
	if err != nil {
		t.Fatalf("drive: %v", err)
	}
	got := float64(res.sentB) * 8 / res.elapsed.Seconds() / 1e6
	if got < mbps*0.5 || got > mbps*1.5 {
		t.Errorf("offered %.1f Mbit/s with --rate %.1f", got, mbps)
	}
}

// A relay that demands a coordinator grant must be REPORTED as such. The
// ephemeral key cannot answer a challenge, and the link then closes — which
// without this flag would read as "the relay dropped everything", i.e. a
// spectacular but entirely fictional network fault.
func TestRelayLegSaysSoWhenTheRelayWantsAuth(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if _, _, err := meshproto.ReadDERPFrame(conn); err != nil {
			return
		}
		_ = meshproto.WriteDERPFrame(conn, meshproto.DERPFrameAuthChallenge, make([]byte, 32))
		time.Sleep(200 * time.Millisecond)
	}()

	res, err := driveRelayLeg(relayTestConfig{addr: ln.Addr().String(), seconds: 2, size: 256, rate: 8})
	if err != nil {
		t.Fatalf("drive: %v", err)
	}
	if !res.authWanted {
		t.Error("the relay sent a challenge and the result does not say so; the run would read as total loss")
	}
}

// The sequence and send offset the RTT depends on must actually be in the frame.
// This is the one piece the echo server cannot verify for us, because it hands
// back whatever it is given.
//
// The offset is nanoseconds since the run's own start, NOT a wall-clock instant.
// The first version encoded UnixNano and rebuilt it with time.Unix on the way
// back, which discards Go's monotonic reading — and Windows' wall clock is
// coarse enough that a loopback round trip then measured as exactly 0s. This
// test's sibling above catches that; this one pins the encoding it depends on.
func TestRelayLegFramesCarrySequenceAndSendOffset(t *testing.T) {
	seen := make(chan []byte, 4)
	addr := startEchoRelay(t, func(p []byte) bool {
		select {
		case seen <- append([]byte(nil), p...):
		default:
		}
		return true
	})
	if _, err := driveRelayLeg(relayTestConfig{addr: addr, seconds: 1, size: 64, rate: 1}); err != nil {
		t.Fatalf("drive: %v", err)
	}
	select {
	case p := <-seen:
		if got := binary.BigEndian.Uint64(p[0:8]); got != 1 {
			t.Errorf("first frame's sequence = %d, want 1", got)
		}
		// An offset, not an instant: the first frame goes out within a second of
		// the run starting, so a UnixNano-sized value here means the encoding
		// regressed to wall-clock time.
		off := time.Duration(binary.BigEndian.Uint64(p[8:16]))
		if off < 0 || off > time.Second {
			t.Errorf("first frame's send offset = %v, want a small offset from the run's start "+
				"(a huge value means it went back to encoding an absolute wall-clock time)", off)
		}
	default:
		t.Fatal("the echo server saw no frames")
	}
}
