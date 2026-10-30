package mesh

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/hostnet"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// This opt-in protocol load test has one production scheduler facing N real
// responders, each with its own identity and UDP socket. It measures discovery
// under saturation, not N complete clients, a coordinator fleet, or WAN NAT.
// Buffer sizing is reduced for the responders so 1000 idle test sockets do not
// reserve the throughput-oriented 7 MiB buffers of a normal client.
func TestProbeProtocolFleet(t *testing.T) {
	raw := os.Getenv("CALABI_TEST_PROBE_FLEET")
	if raw == "" || testing.Short() {
		t.Skip("set CALABI_TEST_PROBE_FLEET=100, 300 or 1000")
	}
	n, err := strconv.Atoi(raw)
	if err != nil || (n != 100 && n != 300 && n != 1000) {
		t.Fatal("CALABI_TEST_PROBE_FLEET must be 100, 300 or 1000")
	}
	var peers []Peer
	for i := 0; i < n; i++ {
		key, err := GenerateDiscoKey()
		if err != nil {
			t.Fatal(err)
		}
		pc, err := hostnet.ListenConfig().ListenPacket(context.Background(), "udp", ":0")
		if err != nil {
			t.Fatal(err)
		}
		conn := pc.(*net.UDPConn)
		_ = conn.SetReadBuffer(64 << 10)
		_ = conn.SetWriteBuffer(64 << 10)
		ms := &magicSock{conn: conn, port: uint16(conn.LocalAddr().(*net.UDPAddr).Port), disco: key}
		defer ms.Close()
		go ms.readLoop()
		peers = append(peers, Peer{DiscoKey: key.Public(), Endpoints: []netip.AddrPort{loopback(ms.LocalPort())}})
	}
	key, _ := GenerateDiscoKey()
	source, err := newMagicSock(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	p := newDiscoProber(source, nil)
	s := newProbeScheduler(p, 50)
	p.scheduler = s
	p.Probe(peers)
	seen := make(chan meshproto.DiscoKey, 2*n)
	source.setPongHandler(func(key meshproto.DiscoKey, tx discoTxID, ep netip.AddrPort) {
		p.onPong(key, tx, ep)
		select {
		case seen <- key:
		default:
		}
	})
	if source.txPackets.Load() != 0 {
		t.Fatal("idle graph sent UDP probes")
	}
	now := time.Now()
	for _, sp := range s.peers {
		sp.active.Store(now.UnixNano())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); s.run(ctx) }()
	defer func() { cancel(); <-done }()
	s.signal()
	unique := make(map[meshproto.DiscoKey]bool, n)
	deadline := time.NewTimer(45 * time.Second)
	defer deadline.Stop()
	for len(unique) < n {
		select {
		case key := <-seen:
			unique[key] = true
		case <-deadline.C:
			t.Fatalf("only %d/%d independent UDP responders answered", len(unique), n)
		}
	}
	elapsed := time.Since(now)
	if float64(s.sent.Load()) > 50*elapsed.Seconds()+10.001 {
		t.Fatal("real protocol exceeded scheduler budget")
	}
	t.Logf("independent_udp_responders=%d authenticated=%d elapsed=%s ping_attempts=%d budget_waits=%d", n, len(unique), elapsed.Round(time.Millisecond), s.sent.Load(), s.limited.Load())
}
