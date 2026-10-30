package relay

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

func TestRelayPerformanceClassifiesPublicHeaders(t *testing.T) {
	h := NewHub(slog.Default(), AuthConfig{})
	for _, v := range []struct {
		kind uint32
		size int
	}{{1, 148}, {2, 92}, {3, 64}, {4, 32}, {4, 1280}, {9, 32}, {1, 32}} {
		p := make([]byte, v.size)
		binary.LittleEndian.PutUint32(p, v.kind)
		h.countPacket(p)
	}
	p := h.Performance()
	if p.HandshakePackets != 3 || p.KeepalivePackets != 1 || p.DataPackets != 1 || p.UnknownPackets != 2 {
		t.Fatalf("bad classification: %+v", p)
	}
}

// Independent TCP clients and node identities use the real forwarding hub.
// Payloads are synthetic ciphertext shapes: this measures forwarding and queues,
// not WireGuard cryptography or authorization-proof throughput.
func TestRelayFleetBaseline(t *testing.T) {
	raw := os.Getenv("CALABI_TEST_RELAY_FLEET")
	if raw == "" || testing.Short() {
		t.Skip("set CALABI_TEST_RELAY_FLEET=100, 300 or 1000")
	}
	n, err := strconv.Atoi(raw)
	if err != nil || (n != 100 && n != 300 && n != 1000) {
		t.Fatal("invalid fleet size")
	}
	h := NewHub(slog.New(slog.NewTextHandler(io.Discard, nil)), AuthConfig{})
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
			go h.Serve(c)
		}
	}()
	keys := make([]meshproto.NodeKey, n)
	clients := make([]net.Conn, n)
	var delivered, pongs atomic.Uint64
	started := time.Now()
	cpuStart, _ := performanceProcessUsage()
	for i := range clients {
		binary.LittleEndian.PutUint32(keys[i][:], uint32(i+1))
		clients[i] = dialFramed(t, ln.Addr().String(), keys[i])
		go func(c net.Conn) {
			for {
				kind, _, err := meshproto.ReadDERPFrame(c)
				if err != nil {
					return
				}
				if kind == meshproto.DERPFrameRecvPacket {
					delivered.Add(1)
				} else if kind == meshproto.DERPFramePong {
					pongs.Add(1)
				}
			}
		}(clients[i])
	}
	deadline := time.Now().Add(10 * time.Second)
	for h.Performance().Clients != n && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if h.Performance().Clients != n {
		t.Fatal("clients were not registered")
	}
	connectTime := time.Since(started)
	workStart := time.Now()
	for round := 0; round < 11; round++ {
		for i, c := range clients {
			kind, size := uint32(4), 1280
			if round == 0 {
				kind, size = 1, 148
			}
			if round == 1 {
				size = 32
			}
			payload := make([]byte, size)
			binary.LittleEndian.PutUint32(payload, kind)
			if err := meshproto.WriteDERPFrame(c, meshproto.DERPFrameSendPacket, meshproto.EncodePacket(keys[(i+1)%n], payload)); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, c := range clients {
		if err := meshproto.WriteDERPFrame(c, meshproto.DERPFramePing, []byte("baseline")); err != nil {
			t.Fatal(err)
		}
	}
	deadline = time.Now().Add(15 * time.Second)
	for (delivered.Load() != uint64(11*n) || pongs.Load() != uint64(n)) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	stats := h.Performance()
	if delivered.Load() != uint64(11*n) || pongs.Load() != uint64(n) || stats.QueueDroppedActive != 0 || stats.OfflinePackets != 0 {
		t.Fatalf("delivery=%d pongs=%d stats=%+v", delivered.Load(), pongs.Load(), stats)
	}
	if stats.KeepalivePackets != uint64(n) || stats.HandshakePackets != uint64(n) || stats.DataPackets != uint64(n*9) {
		t.Fatal("counter mismatch")
	}
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	cpuEnd, rss := performanceProcessUsage()
	t.Logf("clients=%d connect=%s workload=%s forwarded=%d link_pings=%d keepalives=%d handshakes=%d data=%d heap=%d cpu_seconds=%.3f peak_rss=%d", n, connectTime.Round(time.Millisecond), time.Since(workStart).Round(time.Millisecond), delivered.Load(), stats.LinkPings, stats.KeepalivePackets, stats.HandshakePackets, stats.DataPackets, mem.HeapAlloc, cpuEnd-cpuStart, rss)
}
