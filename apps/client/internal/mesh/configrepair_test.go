package mesh

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/hostnet"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"google.golang.org/protobuf/proto"
)

type repairRouting struct {
	recordingRouting
	faultMu                                sync.Mutex
	addFailures, delFailures, linkFailures int
	adds, dels, links                      int
}

type blockingRepairRouting struct {
	repairRouting
	calls            atomic.Int32
	entered, release chan struct{}
}

func (r *blockingRepairRouting) AddSubnetRoutes(p []netip.Prefix) error {
	if r.calls.Add(1) == 2 {
		close(r.entered)
		<-r.release
	}
	return r.repairRouting.AddSubnetRoutes(p)
}

func TestCloseJoinsRepairBeforeTearingDownDatapath(t *testing.T) {
	hostnet.SetInterfaceLister(func() ([]hostnet.Interface, error) { return nil, nil })
	t.Cleanup(func() { hostnet.SetInterfaceLister(nil) })
	r := &blockingRepairRouting{repairRouting: repairRouting{addFailures: 1}, entered: make(chan struct{}), release: make(chan struct{})}
	d, err := NewWGDatapathOnTUN(tuntest.NewChannelTUN().TUN(), r, testKey(1), "127.0.0.1:1", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	unblock := func() { once.Do(func() { close(r.release) }) }
	t.Cleanup(func() { unblock(); d.Close() })
	if err = d.SetConfig(repairConfig()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-r.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("repair did not enter route operation")
	}
	closed := make(chan error, 1)
	go func() { closed <- d.Close() }()
	deadline := time.Now().Add(250 * time.Millisecond)
	for {
		d.bind.mu.Lock()
		running := d.bind.open
		d.bind.mu.Unlock()
		if !running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Close left WireGuard traffic active behind a slow route call")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-closed:
		t.Fatal("Close tore down while repair still modified routes")
	case <-time.After(20 * time.Millisecond):
	}
	unblock()
	select {
	case err = <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join repair")
	}
}

func TestBlockedRouteRepairDoesNotDelayPermissionWithdrawal(t *testing.T) {
	hostnet.SetInterfaceLister(func() ([]hostnet.Interface, error) { return nil, nil })
	t.Cleanup(func() { hostnet.SetInterfaceLister(nil) })
	r := &blockingRepairRouting{repairRouting: repairRouting{addFailures: 1}, entered: make(chan struct{}), release: make(chan struct{})}
	d, err := NewWGDatapathOnTUN(tuntest.NewChannelTUN().TUN(), r, testKey(1), "127.0.0.1:1", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	unblock := func() { once.Do(func() { close(r.release) }) }
	t.Cleanup(func() { unblock(); d.Close() })
	initial := repairConfig()
	initial.FilterEnabled = false
	if err = d.SetConfig(initial); err != nil {
		t.Fatal(err)
	}
	select {
	case <-r.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("repair did not block in OS route call")
	}
	revoked := WGConfig{OverlayAddr: initial.OverlayAddr, FilterEnabled: true, RelayGrant: []byte("new")}
	applied := make(chan error, 1)
	go func() { applied <- d.SetConfig(revoked) }()
	select {
	case err = <-applied:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("slow route repair held up permission withdrawal")
	}
	dump, err := d.dev.IpcGet()
	if err != nil || strings.Contains(dump, "public_key=") {
		t.Fatal("revoked WireGuard peer retained during blocked repair", err)
	}
	d.filter.mu.RLock()
	deny := d.filter.enabled && len(d.filter.rules) == 0
	d.filter.mu.RUnlock()
	if !deny {
		t.Fatal("ACL withdrawal waited for OS call")
	}
	granted := make(chan struct{})
	go func() { d.SetRelayGrant([]byte("latest")); close(granted) }()
	select {
	case <-granted:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("grant refresh waited for OS call")
	}
	unblock()
	awaitConfigRepair(t, d)
	dump, err = d.dev.IpcGet()
	if err != nil || strings.Contains(dump, "public_key=") {
		t.Fatal("old repair restored revoked peer", err)
	}
	d.relays.mu.Lock()
	grant := string(d.relays.grant)
	d.relays.mu.Unlock()
	if grant != "latest" {
		t.Fatal("old repair restored grant")
	}
	r.mu.Lock()
	deleted := len(r.deleted)
	r.mu.Unlock()
	if deleted != 1 {
		t.Fatalf("stale OS route not reconciled after blocked call returned: deletes=%d", deleted)
	}
}

func (r *repairRouting) AddSubnetRoutes(p []netip.Prefix) error {
	r.faultMu.Lock()
	defer r.faultMu.Unlock()
	r.adds++
	if r.addFailures > 0 {
		r.addFailures--
		return errors.New("temporary add failure")
	}
	return r.recordingRouting.AddSubnetRoutes(p)
}
func (r *repairRouting) DelSubnetRoutes(p []netip.Prefix) error {
	r.faultMu.Lock()
	defer r.faultMu.Unlock()
	r.dels++
	if r.delFailures > 0 {
		r.delFailures--
		return errors.New("temporary delete failure")
	}
	return r.recordingRouting.DelSubnetRoutes(p)
}
func (r *repairRouting) ConfigureLink(a netip.Addr) error {
	r.faultMu.Lock()
	defer r.faultMu.Unlock()
	r.links++
	if r.linkFailures > 0 {
		r.linkFailures--
		return errors.New("temporary link failure")
	}
	return r.recordingRouting.ConfigureLink(a)
}
func repairDatapath(t *testing.T, r *repairRouting) *WGDatapath {
	t.Helper()
	hostnet.SetInterfaceLister(func() ([]hostnet.Interface, error) { return nil, nil })
	t.Cleanup(func() { hostnet.SetInterfaceLister(nil) })
	d, err := NewWGDatapathOnTUN(tuntest.NewChannelTUN().TUN(), r, testKey(1), "127.0.0.1:1", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}
func repairConfig() WGConfig {
	return WGConfig{OverlayAddr: netip.MustParseAddr("100.64.0.1"), FilterEnabled: true, RelayGrant: []byte("old"), Peers: []WGPeer{{PublicKey: testKey(2).Public(), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32"), netip.MustParsePrefix("10.99.0.0/24")}}}}
}
func awaitConfigRepair(t *testing.T, d *WGDatapath) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		d.peerConfigMu.Lock()
		done := d.repairDesired == nil && !d.repairRunning
		d.peerConfigMu.Unlock()
		if done {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("configuration repair did not finish")
}

func TestGrantOnlyRefreshDoesNotPreventIndependentRouteRepair(t *testing.T) {
	r := &repairRouting{addFailures: 1}
	d := repairDatapath(t, r)
	m := &meshpb.NetMap{Self: &meshpb.Peer{NodeId: 1, NodeKey: keyB64(1), OverlayAddr: "100.64.0.1"}, FilterEnabled: true, RelayGrant: []byte("old")}
	for i := 2; i <= 20; i++ {
		m.Peers = append(m.Peers, &meshpb.Peer{NodeId: int64(i), NodeKey: keyB64(byte(i)), OverlayAddr: "100.64.0.2", AllowedIps: []string{"100.64.0.2/32"}})
	}
	m.Peers[0].AllowedIps = append(m.Peers[0].AllowedIps, "10.99.0.0/24")
	var e meshproto.NetMapEncoder
	first, next, err := e.Next(m)
	if err != nil {
		t.Fatal(err)
	}
	e = next
	m = proto.Clone(m).(*meshpb.NetMap)
	m.RelayGrant = []byte("renewed")
	second, _, err := e.Next(m)
	if err != nil || !second.GrantOnly {
		t.Fatal("fixture did not produce grant frame", err)
	}
	f := &fakeCoord{reg: &meshpb.RegisterNodeResponse{NodeId: 1, OverlayAddr: "100.64.0.1"}, netmaps: []*meshpb.NetMap{first, second}}
	c := &Controller{Coord: dialFake(t, f), Datapath: d, Routes: RoutePolicy{Accept: true}, Params: RegisterParams{AuthKey: "k", NodeKey: testKey(1).Public(), NodePrivate: testKey(1)}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("controller leaked")
		}
	}()
	deadline := time.Now().Add(time.Second)
	for {
		r.faultMu.Lock()
		started := r.adds > 0
		r.faultMu.Unlock()
		if started {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("initial config not attempted")
		}
		time.Sleep(5 * time.Millisecond)
	}
	awaitConfigRepair(t, d)
	r.faultMu.Lock()
	adds := r.adds
	r.faultMu.Unlock()
	if adds != 2 {
		t.Fatalf("route attempts=%d want 2", adds)
	}
	d.relays.mu.Lock()
	grant := string(d.relays.grant)
	d.relays.mu.Unlock()
	if grant != "renewed" {
		t.Fatal("repair restored old relay grant", grant)
	}
}

func TestConfigRepairRetriesLinkFailures(t *testing.T) {
	r := &repairRouting{linkFailures: 1}
	d := repairDatapath(t, r)
	if err := d.SetConfig(repairConfig()); err == nil {
		t.Fatal("expected transient link error")
	}
	awaitConfigRepair(t, d)
	r.faultMu.Lock()
	links := r.links
	r.faultMu.Unlock()
	if links != 2 {
		t.Fatalf("link attempts=%d", links)
	}
}

func TestConfigRepairWithdrawsRoutesWithoutRestoringRevokedPeers(t *testing.T) {
	r := &repairRouting{}
	d := repairDatapath(t, r)
	initial := repairConfig()
	if err := d.SetConfig(initial); err != nil {
		t.Fatal(err)
	}
	r.faultMu.Lock()
	r.delFailures = 1
	r.faultMu.Unlock()
	revoked := WGConfig{OverlayAddr: initial.OverlayAddr, FilterEnabled: true, RelayGrant: []byte("new")}
	if err := d.SetConfig(revoked); err != nil {
		t.Fatal(err)
	}
	d.SetRelayGrant([]byte("latest"))
	awaitConfigRepair(t, d)
	r.faultMu.Lock()
	adds, dels := r.adds, r.dels
	r.faultMu.Unlock()
	if adds != 1 || dels != 2 {
		t.Fatalf("unexpected repair operations adds=%d dels=%d", adds, dels)
	}
	dump, err := d.dev.IpcGet()
	if err != nil || strings.Contains(dump, "public_key=") {
		t.Fatal("revoked peer restored", err)
	}
	d.filter.mu.RLock()
	denyAll := d.filter.enabled && len(d.filter.rules) == 0
	d.filter.mu.RUnlock()
	if !denyAll {
		t.Fatal("repair reopened packet filter")
	}
	d.relays.mu.Lock()
	grant := string(d.relays.grant)
	d.relays.mu.Unlock()
	if grant != "latest" {
		t.Fatal("stale grant restored")
	}
}

func TestNewConfigSupersedesFailedApplyAndCloseStopsRepair(t *testing.T) {
	r := &repairRouting{addFailures: 100}
	d := repairDatapath(t, r)
	if err := d.SetConfig(repairConfig()); err != nil {
		t.Fatal(err)
	}
	if err := d.SetConfig(WGConfig{OverlayAddr: netip.MustParseAddr("100.64.0.1"), FilterEnabled: true}); err != nil {
		t.Fatal(err)
	}
	awaitConfigRepair(t, d)
	r.faultMu.Lock()
	adds := r.adds
	r.faultMu.Unlock()
	if adds != 1 {
		t.Fatal("obsolete route retried")
	}
	if err := d.SetConfig(repairConfig()); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d.peerConfigMu.Lock()
	running := d.repairRunning
	retained := d.repairDesired != nil
	d.peerConfigMu.Unlock()
	if running || retained {
		t.Fatal("Close retained repair job or graph")
	}
	if err := d.SetConfig(repairConfig()); err == nil {
		t.Fatal("closed datapath accepted config")
	}
}
