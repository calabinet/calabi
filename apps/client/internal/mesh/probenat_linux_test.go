package mesh

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	"github.com/calabinet/calabi/pkg/mesh-proto/stun"
	"github.com/calabinet/calabi/pkg/relay"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

type natDeviceConfig struct {
	Index     int
	Own       PrivateKey
	Disco     DiscoPrivateKey
	Peer      meshproto.NodeKey
	PeerDisco meshproto.DiscoKey
	LAN       string
	PeerLAN   string
	Relay     string
	Legacy    bool
	Phone     bool
}
type natDeviceReport struct {
	Ready          bool
	Endpoint       string
	Port           uint16
	Received       uint64
	Path           string
	DirectEndpoint string
	Handshake      int64
	RxBytes        int64
	TxBytes        int64
	Datapath       DatapathStats
}

func natJSONWrite(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err = os.WriteFile(path+".new", b, 0600); err != nil {
		return err
	}
	return os.Rename(path+".new", path)
}
func natJSONRead(path string, v any) bool {
	b, err := os.ReadFile(path)
	return err == nil && json.Unmarshal(b, v) == nil
}

// Executed only as a subprocess inside its own Linux network namespace. Using
// a whole process makes all Go-created sockets inherit that namespace, including
// the relay pool's background dials; switching only one Go thread would not.
func TestProbeNATDevice(t *testing.T) {
	dir := os.Getenv("CALABI_TEST_NAT_DEVICE")
	if dir == "" {
		t.Skip("NAT harness child only")
	}
	var cfg natDeviceConfig
	if !natJSONRead(filepath.Join(dir, "config.json"), &cfg) {
		t.Fatal("missing child config")
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	channel := tuntest.NewChannelTUN()
	d, err := NewWGDatapathOnTUN(channel.TUN(), &recordingRouting{}, cfg.Own, cfg.Relay, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ms, err := newMagicSock(cfg.Disco, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ms.Close()
	ep, err := ms.Reflexive(ctx, netip.MustParseAddrPort("198.18.0.1:3478"))
	if err != nil {
		t.Fatal(err)
	}
	p := newDiscoProber(ms, nil)
	if !cfg.Legacy {
		rate := 50
		if cfg.Phone {
			rate = 20
		}
		p.scheduler = newProbeScheduler(p, rate)
	}
	d.attachDirect(ms, p)
	defer d.detachDirect()
	if err := natJSONWrite(filepath.Join(dir, "report.json"), natDeviceReport{Ready: true, Endpoint: ep.String(), Port: ms.LocalPort()}); err != nil {
		t.Fatal(err)
	}
	var peerReport natDeviceReport
	for !natJSONRead(filepath.Join(dir, "peer.json"), &peerReport) {
		time.Sleep(20 * time.Millisecond)
	}
	peerIP := netip.MustParseAddr(fmt.Sprintf("100.64.0.%d", 12-cfg.Index))
	ownIP := netip.MustParseAddr(fmt.Sprintf("100.64.0.%d", 11+cfg.Index))
	peers := []Peer{{DiscoKey: cfg.PeerDisco, Endpoints: []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr(cfg.PeerLAN), peerReport.Port), netip.MustParseAddrPort(peerReport.Endpoint)}}}
	p.Probe(peers)
	keepalive := time.Duration(0)
	if cfg.Legacy {
		keepalive = 25 * time.Second
	}
	wgcfg := WGConfig{NodeKey: cfg.Own.Public(), OverlayAddr: ownIP, SelfRelay: cfg.Relay, RelayByRegion: map[string]string{"test": cfg.Relay}, Peers: []WGPeer{{PublicKey: cfg.Peer, DiscoKey: cfg.PeerDisco, DERPHome: "test", PersistentKeepalive: keepalive, AllowedIPs: []netip.Prefix{netip.PrefixFrom(peerIP, 32)}}}}
	if err := d.SetConfig(wgcfg); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); p.run(ctx, probeInterval, func() []Peer { return peers }) }()
	defer func() { cancel(); <-done }()
	var received atomic.Uint64
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-channel.Inbound:
				if !ok {
					return
				}
				received.Add(1)
			}
		}
	}()
	lastCommand := ""
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		if b, err := os.ReadFile(filepath.Join(dir, "command")); err == nil && string(b) != lastCommand {
			lastCommand = string(b)
			select {
			case channel.Outbound <- tuntest.Ping(peerIP, ownIP):
			case <-time.After(3 * time.Second):
				t.Fatal("child TUN stalled")
			}
		}
		st := d.Snapshot()
		report := natDeviceReport{Ready: true, Endpoint: ep.String(), Port: ms.LocalPort(), Received: received.Load(), Datapath: st.Datapath}
		if len(st.Peers) > 0 {
			peer := st.Peers[0]
			report.Path = peer.Path
			report.DirectEndpoint = peer.Endpoint
			report.Handshake = peer.LastHandshakeSec
			report.RxBytes = peer.RxBytes
			report.TxBytes = peer.TxBytes
		}
		if err := natJSONWrite(filepath.Join(dir, "report.json"), report); err != nil {
			t.Fatal(err)
		}
	}
}

func natCommand(t *testing.T, args ...string) {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %v: %s", args, err, out)
	}
}
func natIn(t *testing.T, ns string, args ...string) {
	t.Helper()
	natCommand(t, append([]string{"ip", "netns", "exec", ns}, args...)...)
}

func setupNATTopology(t *testing.T, mode string) {
	t.Helper()
	for _, ns := range []string{"pa", "pb", "pra", "prb"} {
		natCommand(t, "ip", "netns", "add", ns)
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
		natCommand(t, "ip", "-n", ns, "link", "set", "lo", "up")
	}
	natCommand(t, "ip", "link", "add", "pwan", "type", "bridge")
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", "pwan").Run() })
	natCommand(t, "ip", "addr", "add", "198.18.0.1/24", "dev", "pwan")
	natCommand(t, "ip", "link", "set", "pwan", "up")
	if mode == "lan" {
		natCommand(t, "ip", "link", "add", "plan", "type", "bridge")
		t.Cleanup(func() { _ = exec.Command("ip", "link", "del", "plan").Run() })
		natCommand(t, "ip", "addr", "add", "10.0.0.1/24", "dev", "plan")
		natCommand(t, "ip", "link", "set", "plan", "up")
		for i, ns := range []string{"pa", "pb"} {
			host := "h" + ns
			dev := "d" + ns
			natCommand(t, "ip", "link", "add", host, "type", "veth", "peer", "name", dev)
			t.Cleanup(func() { _ = exec.Command("ip", "link", "del", host).Run() })
			natCommand(t, "ip", "link", "set", host, "master", "plan")
			natCommand(t, "ip", "link", "set", host, "up")
			natCommand(t, "ip", "link", "set", dev, "netns", ns)
			natCommand(t, "ip", "-n", ns, "addr", "add", fmt.Sprintf("10.0.0.%d/24", i+2), "dev", dev)
			natCommand(t, "ip", "-n", ns, "link", "set", dev, "up")
			natCommand(t, "ip", "-n", ns, "route", "add", "default", "via", "10.0.0.1")
		}
		return
	}
	for i, ns := range []string{"pa", "pb"} {
		router := []string{"pra", "prb"}[i]
		host := "w" + ns
		wan := "r" + ns
		lan := "l" + ns
		dev := "d" + ns
		natCommand(t, "ip", "link", "add", host, "type", "veth", "peer", "name", wan)
		t.Cleanup(func() { _ = exec.Command("ip", "link", "del", host).Run() })
		natCommand(t, "ip", "link", "set", host, "master", "pwan")
		natCommand(t, "ip", "link", "set", host, "up")
		natCommand(t, "ip", "link", "set", wan, "netns", router)
		natCommand(t, "ip", "-n", router, "addr", "add", fmt.Sprintf("198.18.0.%d/24", i+2), "dev", wan)
		natCommand(t, "ip", "-n", router, "link", "set", wan, "up")
		natCommand(t, "ip", "link", "add", lan, "type", "veth", "peer", "name", dev)
		natCommand(t, "ip", "link", "set", lan, "netns", router)
		natCommand(t, "ip", "link", "set", dev, "netns", ns)
		natCommand(t, "ip", "-n", router, "addr", "add", "10.0.0.1/24", "dev", lan)
		natCommand(t, "ip", "-n", router, "link", "set", lan, "up")
		natCommand(t, "ip", "-n", ns, "addr", "add", "10.0.0.2/24", "dev", dev)
		natCommand(t, "ip", "-n", ns, "link", "set", dev, "up")
		natCommand(t, "ip", "-n", ns, "route", "add", "default", "via", "10.0.0.1")
		natIn(t, router, "sysctl", "-w", "net.ipv4.ip_forward=1")
		public := fmt.Sprintf("198.18.0.%d", i+2)
		port := 51000 + i*1000
		if mode == "symmetric" && i == 0 {
			natIn(t, router, "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", wan, "-p", "udp", "-d", "198.18.0.1", "--dport", "3478", "-j", "SNAT", "--to-source", public+":45000")
			natIn(t, router, "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", wan, "-p", "udp", "-j", "SNAT", "--to-source", public+":45001")
		} else {
			natIn(t, router, "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", wan, "-p", "udp", "-j", "SNAT", "--to-source", public+":"+strconv.Itoa(port))
		}
		natIn(t, router, "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", wan, "-j", "MASQUERADE")
	}
}

// Run only inside an explicitly disposable, privileged Linux container. The
// peers have real separate network namespaces, Linux conntrack/NAT and real WG;
// only the inner OS TUN is in memory, so no host routing is modified.
func TestProbeLinuxNATIntegration(t *testing.T) {
	if os.Getenv("CALABI_TEST_NAT_SANDBOX") != "1" || testing.Short() {
		t.Skip("disposable Linux NAT sandbox only")
	}
	for _, mode := range []string{"lan", "cone", "symmetric", "mixed", "phone"} {
		t.Run(mode, func(t *testing.T) {
			setupNATTopology(t, mode)
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			ln, err := net.Listen("tcp", "198.18.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			hub := relay.NewHub(logger, relay.AuthConfig{})
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					go hub.Serve(c)
				}
			}()
			stunConn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("198.18.0.1:3478")))
			if err != nil {
				t.Fatal(err)
			}
			defer stunConn.Close()
			go func() {
				buf := make([]byte, 1500)
				for {
					n, from, err := stunConn.ReadFromUDPAddrPort(buf)
					if err != nil {
						return
					}
					if tx, ok := stun.IsBindingRequest(buf[:n]); ok {
						_, _ = stunConn.WriteToUDPAddrPort(stun.BindingResponse(tx, netip.AddrPortFrom(from.Addr().Unmap(), from.Port())), from)
					}
				}
			}()
			keys := [2]PrivateKey{}
			discos := [2]DiscoPrivateKey{}
			for i := 0; i < 2; i++ {
				keys[i], _ = GenerateKey()
				discos[i], _ = GenerateDiscoKey()
			}
			var dirs [2]string
			var logs [2]bytes.Buffer
			for i, ns := range []string{"pa", "pb"} {
				dirs[i] = t.TempDir()
				lan, peerLAN := "10.0.0.2", "10.0.0.2"
				if mode == "lan" {
					lan = fmt.Sprintf("10.0.0.%d", i+2)
					peerLAN = fmt.Sprintf("10.0.0.%d", 3-i)
				}
				cfg := natDeviceConfig{Index: i, Own: keys[i], Disco: discos[i], Peer: keys[1-i].Public(), PeerDisco: discos[1-i].Public(), LAN: lan, PeerLAN: peerLAN, Relay: ln.Addr().String(), Legacy: mode == "mixed" && i == 1, Phone: mode == "phone" && i == 1}
				if err := natJSONWrite(filepath.Join(dirs[i], "config.json"), cfg); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command("ip", "netns", "exec", ns, os.Args[0], "-test.run=^TestProbeNATDevice$", "-test.timeout=8m")
				cmd.Env = append(os.Environ(), "CALABI_TEST_NAT_DEVICE="+dirs[i])
				cmd.Stdout = &logs[i]
				cmd.Stderr = &logs[i]
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				defer func() {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
					if t.Failed() {
						t.Log(logs[i].String())
					}
				}()
			}
			read := func(i int) natDeviceReport {
				var r natDeviceReport
				natJSONRead(filepath.Join(dirs[i], "report.json"), &r)
				return r
			}
			wait := func(label string, d time.Duration, predicate func() bool) {
				t.Helper()
				until := time.Now().Add(d)
				for time.Now().Before(until) {
					if predicate() {
						return
					}
					time.Sleep(50 * time.Millisecond)
				}
				t.Fatalf("%s timed out: A=%+v B=%+v", label, read(0), read(1))
			}
			wait("ready", 10*time.Second, func() bool { return read(0).Ready && read(1).Ready })
			for i := 0; i < 2; i++ {
				if mode != "lan" && !(mode == "symmetric" && i == 0) {
					port := 51000 + i*1000
					natIn(t, []string{"pra", "prb"}[i], "iptables", "-t", "nat", "-A", "PREROUTING", "-p", "udp", "--dport", strconv.Itoa(port), "-j", "DNAT", "--to-destination", "10.0.0.2:"+strconv.Itoa(int(read(i).Port)))
				}
				if err := natJSONWrite(filepath.Join(dirs[i], "peer.json"), read(1-i)); err != nil {
					t.Fatal(err)
				}
			}
			send := func(i int) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dirs[i], "command"), []byte(strconv.FormatInt(time.Now().UnixNano(), 10)), 0600); err != nil {
					t.Fatal(err)
				}
			}
			started := time.Now()
			send(0)
			wait("first business", 10*time.Second, func() bool { return read(1).Received > 0 })
			first := time.Since(started)
			wait("bidirectional direct", 10*time.Second, func() bool { return read(0).Path == PathDirect && read(1).Path == PathDirect })
			if mode == "lan" && !strings.HasPrefix(read(0).DirectEndpoint, "10.0.0.3:") {
				t.Fatal("same LAN did not use private path")
			}
			if mode == "symmetric" && read(1).DirectEndpoint != "198.18.0.2:45001" {
				t.Fatalf("symmetric learned endpoint=%s", read(1).DirectEndpoint)
			}
			if (mode == "cone" || mode == "mixed") && (read(0).DirectEndpoint != "198.18.0.3:52000" || read(1).DirectEndpoint != "198.18.0.2:51000") {
				t.Fatalf("wrong NAT source mapping A=%s B=%s", read(0).DirectEndpoint, read(1).DirectEndpoint)
			}
			if mode != "lan" && (strings.HasPrefix(read(0).DirectEndpoint, "10.") || strings.HasPrefix(read(1).DirectEndpoint, "10.")) {
				t.Fatal("overlapping private IP falsely authenticated")
			}
			before := read(0)
			send(1)
			wait("reverse business", 5*time.Second, func() bool { return read(0).Received > before.Received })
			if mode == "cone" || mode == "symmetric" || mode == "mixed" || mode == "phone" {
				// Stop traffic long enough for activity and path freshness to expire.
				time.Sleep(80 * time.Second)
				wait("idle", 5*time.Second, func() bool { return read(0).Datapath.ProbeActive == 0 && read(1).Datapath.ProbeActive == 0 })
				_ = exec.Command("ip", "netns", "exec", "pra", "conntrack", "-D", "-p", "udp").Run()
				_ = exec.Command("ip", "netns", "exec", "prb", "conntrack", "-D", "-p", "udp").Run()
				beforeB := read(1)
				send(0)
				wait("business after idle", 10*time.Second, func() bool { return read(1).Received > beforeB.Received })
				wait("direct after idle", 10*time.Second, func() bool { return read(0).Path == PathDirect && read(1).Path == PathDirect })
			}
			if mode == "cone" {
				natIn(t, "pra", "iptables", "-I", "FORWARD", "1", "-p", "udp", "-j", "DROP")
				wait("stale path fallback", 16*time.Second, func() bool { return read(0).Path == PathRelay })
				beforeB := read(1)
				send(0)
				wait("relay business", 10*time.Second, func() bool { return read(1).Received > beforeB.Received })
				natIn(t, "pra", "iptables", "-D", "FORWARD", "-p", "udp", "-j", "DROP")
				wait("direct recovery", 15*time.Second, func() bool { return read(0).Path == PathDirect })
			}
			t.Logf("mode=%s first_business=%s A=%s B=%s relay=%+v", mode, first.Round(time.Millisecond), read(0).DirectEndpoint, read(1).DirectEndpoint, hub.Performance())
		})
	}
}
