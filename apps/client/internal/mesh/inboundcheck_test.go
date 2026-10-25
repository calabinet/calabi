package mesh

import (
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestApplicationPolicyRechecksRevocationWithoutFlowExemption(t *testing.T) {
	ip := netip.MustParseAddr("100.64.0.9")
	d := &WGDatapath{filter: &PacketFilter{}}
	if !d.IncomingTCPAllowed(ip, 17401) {
		t.Fatal("default mesh policy was not inherited")
	}
	d.filter.SetRules(true, []FilterRule{rule(ip.String()+"/32", PortRange{First: 17401, Last: 17401, Proto: "tcp"})})
	if !d.IncomingTCPAllowed(ip, 17401) || d.IncomingTCPAllowed(ip, 17402) {
		t.Fatal("wrong port policy")
	}
	d.filter.SetRules(true, nil)
	if d.IncomingTCPAllowed(ip, 17401) {
		t.Fatal("ACL revocation was ignored")
	}
	d.filter.SetRules(false, nil)
	d.filter.SetShields(true)
	if d.IncomingTCPAllowed(ip, 17401) {
		t.Fatal("block incoming was ignored without ACLs")
	}
	var absent *WGDatapath
	if absent.IncomingTCPAllowed(ip, 17401) {
		t.Fatal("absent datapath allowed incoming")
	}
}

func TestDevicePeerAddressDoesNotUseAdvertisedRoutes(t *testing.T) {
	var key meshproto.NodeKey
	key[0] = 7
	c := &Controller{}
	c.setPeers([]Peer{{NodeKey: key, Overlay: netip.MustParseAddr("100.64.0.7"), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("192.0.2.99/32"), netip.MustParsePrefix("100.64.0.7/32")}}})
	if c.DeviceKeyForIP(netip.MustParseAddr("100.64.0.7")) != key.String() {
		t.Fatal("device identity lost")
	}
	if c.DeviceKeyForIP(netip.MustParseAddr("192.0.2.99")) != "" {
		t.Fatal("advertised host route became a device identity")
	}
	c.setPeers(nil)
	if c.DeviceKeyForIP(netip.MustParseAddr("100.64.0.7")) != "" {
		t.Fatal("removed device retained authorization")
	}
}

func TestInboundPolicyLocalHandlerFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		source any
		query  string
		code   int
		result string
	}{
		{nil, "?source=100.64.0.9&port=17401", 503, ""},
		{&WGDatapath{}, "?source=100.64.0.9&port=17401", 200, `"allowed":false`},
		{&WGDatapath{filter: &PacketFilter{}}, "?source=100.64.0.9&port=17401", 200, `"allowed":true`},
		{nil, "?source=100.64.0.0/24&port=17401", 400, ""},
		{nil, "?source=100.64.0.9&port=0", 400, ""},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/v1/mesh/inbound-check"+tc.query, nil)
		InboundPolicyHandler(tc.source)(w, r)
		if w.Code != tc.code || (tc.result != "" && !strings.Contains(w.Body.String(), tc.result)) {
			t.Fatalf("%s: %d %s", tc.query, w.Code, w.Body.String())
		}
	}
}
