package mesh

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/calabinet/calabi/pkg/relay"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

type probeBusinessPair struct {
	channels  [2]*tuntest.ChannelTUN
	devices   [2]*WGDatapath
	probers   [2]*discoProber
	sockets   [2]*magicSock
	addresses [2]netip.Addr
	cleanup   func()
}

func newProbeBusinessPair(t *testing.T, adaptive bool) *probeBusinessPair {
	return newProbeBusinessPairAtRate(t, adaptive, 50)
}

func newProbeBusinessPairAtRate(t *testing.T, adaptive bool, rate int) *probeBusinessPair {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	pair := &probeBusinessPair{addresses: [2]netip.Addr{netip.MustParseAddr("100.64.0.21"), netip.MustParseAddr("100.64.0.22")}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := relay.NewHub(logger, relay.AuthConfig{})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go h.Serve(c)
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{}, 2)
	keys := [2]PrivateKey{}
	discos := [2]DiscoPrivateKey{}
	for i := 0; i < 2; i++ {
		keys[i], _ = GenerateKey()
		discos[i], _ = GenerateDiscoKey()
		pair.channels[i] = tuntest.NewChannelTUN()
		d, err := NewWGDatapathOnTUN(pair.channels[i].TUN(), &recordingRouting{}, keys[i], ln.Addr().String(), logger)
		if err != nil {
			t.Fatal(err)
		}
		pair.devices[i] = d
		ms, err := newMagicSock(discos[i], nil)
		if err != nil {
			t.Fatal(err)
		}
		pair.sockets[i] = ms
		p := newDiscoProber(ms, nil)
		if adaptive {
			p.scheduler = newProbeScheduler(p, rate)
		}
		pair.probers[i] = p
		d.attachDirect(ms, p)
	}
	for i := 0; i < 2; i++ {
		j := 1 - i
		keep := time.Duration(0)
		if !adaptive {
			keep = 25 * time.Second
		}
		cfg := WGConfig{NodeKey: keys[i].Public(), OverlayAddr: pair.addresses[i], SelfRelay: ln.Addr().String(), RelayByRegion: map[string]string{"test": ln.Addr().String()}, Peers: []WGPeer{{PublicKey: keys[j].Public(), DiscoKey: discos[j].Public(), DERPHome: "test", PersistentKeepalive: keep, AllowedIPs: []netip.Prefix{netip.PrefixFrom(pair.addresses[j], 32)}}}}
		if err := pair.devices[i].SetConfig(cfg); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		j := 1 - i
		peers := []Peer{{DiscoKey: discos[j].Public(), Endpoints: []netip.AddrPort{loopback(pair.sockets[j].LocalPort())}}}
		p := pair.probers[i]
		p.Probe(peers)
		go func() {
			defer func() { done <- struct{}{} }()
			p.run(ctx, probeInterval, func() []Peer { return peers })
		}()
	}
	pair.cleanup = func() {
		cancel()
		<-done
		<-done
		for i := 0; i < 2; i++ {
			pair.devices[i].Close()
			pair.sockets[i].Close()
		}
		ln.Close()
	}
	return pair
}

func (p *probeBusinessPair) transmit(t *testing.T) time.Duration {
	t.Helper()
	packet := tuntest.Ping(p.addresses[1], p.addresses[0])
	started := time.Now()
	select {
	case p.channels[0].Outbound <- packet:
	case <-time.After(3 * time.Second):
		t.Fatal("first access TUN stalled")
	}
	select {
	case got := <-p.channels[1].Inbound:
		if string(got) != string(packet) {
			t.Fatal("first access payload changed")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("first access delivery failed")
	}
	return time.Since(started)
}

func (p *probeBusinessPair) throughput(t *testing.T) float64 {
	t.Helper()
	until := time.Now().Add(5 * time.Second)
	for p.devices[0].Snapshot().Peers[0].Path != PathDirect && time.Now().Before(until) {
		time.Sleep(5 * time.Millisecond)
	}
	if p.devices[0].Snapshot().Peers[0].Path != PathDirect {
		t.Fatal("throughput path not direct")
	}
	packet := append(tuntest.Ping(p.addresses[1], p.addresses[0]), make([]byte, 1200-28)...)
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[10], packet[11] = 0, 0
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(packet[10:12], ^uint16(sum))
	const count = 8192
	credits := make(chan struct{}, 32)
	for i := 0; i < cap(credits); i++ {
		credits <- struct{}{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	finished := make(chan struct{})
	started := time.Now()
	go func() {
		defer close(finished)
		for i := 0; i < count; i++ {
			select {
			case <-credits:
			case <-ctx.Done():
				return
			}
			select {
			case p.channels[0].Outbound <- packet:
			case <-ctx.Done():
				return
			}
		}
	}()
	for i := 0; i < count; i++ {
		select {
		case b := <-p.channels[1].Inbound:
			if len(b) != len(packet) {
				t.Fatal("throughput packet truncated")
			}
			credits <- struct{}{}
		case <-ctx.Done():
			t.Fatalf("throughput stalled after %d packets", i)
		}
	}
	<-finished
	return float64(count*len(packet)) * 8 / time.Since(started).Seconds() / 1e6
}

func TestProbeFirstAccessAndThroughputBaseline(t *testing.T) {
	if os.Getenv("CALABI_TEST_PROBE_LATENCY") != "1" || testing.Short() {
		t.Skip("set CALABI_TEST_PROBE_LATENCY=1")
	}
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	var cold, warm [2][]time.Duration
	var rates [2][]float64
	// Alternate AB/BA order so allocator state, CPU frequency and host load do
	// not systematically favor whichever implementation runs first.
	for i := 0; i < 20; i++ {
		for _, mode := range []int{i % 2, 1 - i%2} {
			func() {
				pair := newProbeBusinessPair(t, mode == 1)
				defer pair.cleanup()
				cold[mode] = append(cold[mode], pair.transmit(t))
				warm[mode] = append(warm[mode], pair.transmit(t))
				if i < 9 {
					rates[mode] = append(rates[mode], pair.throughput(t))
				}
			}()
		}
	}
	p95 := func(v []time.Duration) time.Duration {
		sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
		return v[(len(v)*95+99)/100-1]
	}
	for i := 0; i < 2; i++ {
		sort.Float64s(rates[i])
	}
	ratio := rates[1][len(rates[1])/2] / rates[0][len(rates[0])/2]
	t.Logf("samples_per_mode=20 legacy_cold_p95=%s adaptive_cold_p95=%s legacy_warm_p95=%s adaptive_warm_p95=%s legacy_throughput_median=%.2f adaptive_throughput_median=%.2f ratio=%.4f", p95(cold[0]), p95(cold[1]), p95(warm[0]), p95(warm[1]), rates[0][4], rates[1][4], ratio)
	t.Logf("throughput_mbit_legacy=%v adaptive=%v", rates[0], rates[1])
	if p95(cold[1]) > p95(cold[0])+100*time.Millisecond || p95(warm[1]) > p95(warm[0])+100*time.Millisecond {
		t.Fatal("first access regressed by over 100ms")
	}
	if ratio < .95 {
		t.Fatal("controlled direct throughput below 95 percent of baseline")
	}
}
