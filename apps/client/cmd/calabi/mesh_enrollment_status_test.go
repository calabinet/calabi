package main

import (
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/calabinet/calabi/apps/client/internal/mesh"
)

// Use an in-memory TUN and routing so this exercises the real data plane without
// changing the host's interfaces or routes.
type enrollmentTestRouting struct{}

func (enrollmentTestRouting) ConfigureLink(netip.Addr) error       { return nil }
func (enrollmentTestRouting) AddSubnetRoutes([]netip.Prefix) error { return nil }
func (enrollmentTestRouting) DelSubnetRoutes([]netip.Prefix) error { return nil }
func (enrollmentTestRouting) OwnSocketsBypassTunnel() bool         { return true }
func (enrollmentTestRouting) EnableExitRoutes([]netip.Addr, []netip.Prefix) (func(), error) {
	return func() {}, nil
}

func TestMeshStatusNeedsConfigurationBeforeReportingConnected(t *testing.T) {
	key, err := mesh.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	dp, err := mesh.NewWGDatapathOnTUN(tuntest.NewChannelTUN().TUN(), enrollmentTestRouting{}, key, "", quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dp.Close() })
	r := newMeshRunner(quietLogger(), testMeshConfig())
	r.setDP(dp)
	if st := r.MeshStatus(); st.Up || st.NetmapSeen || st.Overlay != "" {
		t.Fatalf("TUN alone reported connected: %+v", st)
	}
	if err := dp.SetConfig(mesh.WGConfig{NodeKey: key.Public(), OverlayAddr: netip.MustParseAddr("100.64.0.7")}); err != nil {
		t.Fatal(err)
	}
	if st := r.MeshStatus(); !st.Up || !st.NetmapSeen || st.Overlay != "100.64.0.7" {
		t.Fatalf("configured data plane not connected: %+v", st)
	}
}
