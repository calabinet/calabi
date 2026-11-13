package mobile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
)

func TestRDPPreparationUsesAuthenticatedMeshIdentity(t *testing.T) {
	useMemoryTUNs(t)
	key, err := meshproto.ParseNodeKey(testNodeKey(2))
	if err != nil {
		t.Fatal(err)
	}
	other, _ := meshproto.ParseNodeKey(testNodeKey(3))
	missing, _ := meshproto.ParseNodeKey(testNodeKey(4))
	linux, _ := meshproto.ParseNodeKey(testNodeKey(5))
	pin := bytes.Repeat([]byte{0xab}, 32)
	_, address := startFakeCoord(t, &meshpb.NetMap{
		Self: &meshpb.Peer{NodeId: 11, OverlayAddr: "100.64.0.7"},
		Peers: []*meshpb.Peer{
			{NodeId: 12, NodeKey: key.String(), OverlayAddr: "100.64.0.8", AllowedIps: []string{"100.64.0.8/32"}, Name: "workstation", Os: "windows", SameOwner: true, RdpCertificateSha256: pin},
			{NodeId: 13, NodeKey: other.String(), OverlayAddr: "100.64.0.9", AllowedIps: []string{"100.64.0.9/32"}, Os: "windows", SameOwner: false, RdpCertificateSha256: pin},
			{NodeId: 14, NodeKey: missing.String(), OverlayAddr: "100.64.0.10", AllowedIps: []string{"100.64.0.10/32"}, Os: "windows", SameOwner: true},
			{NodeId: 15, NodeKey: linux.String(), OverlayAddr: "100.64.0.11", AllowedIps: []string{"100.64.0.11/32"}, Os: "linux", SameOwner: true, RdpCertificateSha256: pin},
		},
	})
	c := newTestCore(t, &fakeBFF{enrollment: fmt.Sprintf(`{"enabled":true,"coord_addr":%q,"relay_addr":"127.0.0.1:1","org_id":7}`, address)}, &fakePlatform{})
	c.cfg.RemoteDesktopP0 = true
	c.api = c.routes()
	post := func(path string, value map[string]any) (int, map[string]any) {
		b, _ := json.Marshal(value)
		return call(t, c, "POST", "/v1/remote/rdp/"+path, string(b))
	}
	if code, _ := post("prepare", map[string]any{"device_key": key.String()}); code != 403 {
		t.Fatalf("disconnected prepare = %d", code)
	}
	signIn(t, c)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "RDP identity", func() bool { _, err := c.resolveRDP(key.String()); return err == nil })
	for _, forbidden := range []string{other.String(), missing.String(), linux.String(), "100.64.0.8", "unregistered"} {
		if code, _ := post("prepare", map[string]any{"device_key": forbidden}); code != 403 {
			t.Errorf("forbidden target %q = %d", forbidden, code)
		}
	}
	for _, field := range []string{"host", "port", "password", "ignore_certificate"} {
		if code, _ := post("prepare", map[string]any{"device_key": key.String(), field: "forbidden"}); code != 400 {
			t.Errorf("unexpected %s accepted: %d", field, code)
		}
	}
	code, prepared := post("prepare", map[string]any{"device_key": key.String()})
	if code != 200 || prepared["host"] != "100.64.0.8" || prepared["local"] != "100.64.0.7" || prepared["port"] != float64(3389) || prepared["certificate_sha256"] != strings.Repeat("ab", 32) {
		t.Fatalf("prepared = %d %v", code, prepared)
	}
	for _, invalidPort := range []any{0, -1, 65536, 3390.5, "3390"} {
		if code, _ := post("prepare", map[string]any{"device_key": key.String(), "port": invalidPort}); code != 400 {
			t.Errorf("invalid port %v = %d", invalidPort, code)
		}
	}
	customCode, custom := post("prepare", map[string]any{"device_key": key.String(), "port": 3390})
	if customCode != 200 || custom["port"] != float64(3390) || custom["host"] != "100.64.0.8" {
		t.Fatalf("custom endpoint = %d %v", customCode, custom)
	}
	if code, _ := post("verify", map[string]any{"token": custom["token"], "certificate_sha256": custom["certificate_sha256"]}); code != 403 {
		t.Fatal("custom ticket accepted a different/default port")
	}
	if code, _ := post("verify", map[string]any{"token": custom["token"], "certificate_sha256": custom["certificate_sha256"], "port": 3390}); code != 200 {
		t.Fatal("custom ticket rejected its port")
	}
	post("close", map[string]any{"token": custom["token"]})
	token := prepared["token"]
	if code, _ := post("verify", map[string]any{"token": token, "certificate_sha256": strings.Repeat("0", 64)}); code != 403 {
		t.Fatalf("wrong certificate accepted: %d", code)
	}
	if code, _ := post("verify", map[string]any{"token": token, "certificate_sha256": prepared["certificate_sha256"]}); code != 200 {
		t.Fatalf("correct certificate rejected: %d", code)
	}
	e := c.currentEngine()
	e.mu.Lock()
	previousState := e.state
	e.state = stateConnecting
	e.mu.Unlock()
	if code, body := post("verify", map[string]any{"token": token, "certificate_sha256": prepared["certificate_sha256"]}); code != 503 || body["reason"] != "mesh_reconnecting" {
		t.Fatalf("temporary mesh reconnect must pause, got %d", code)
	}
	if code, _ := post("verify", map[string]any{"token": token, "certificate_sha256": strings.Repeat("0", 64)}); code != 403 {
		t.Fatal("temporary mesh reconnect bypassed pin check")
	}
	e.mu.Lock()
	e.state = stateDisabled
	e.mu.Unlock()
	if code, _ := post("verify", map[string]any{"token": token, "certificate_sha256": prepared["certificate_sha256"]}); code != 403 {
		t.Fatal("disabled identity was treated as a network interruption")
	}
	e.mu.Lock()
	e.state = stateConnected
	previousController := e.ctrl
	e.ctrl = nil
	e.mu.Unlock()
	if code, _ := post("verify", map[string]any{"token": token, "certificate_sha256": prepared["certificate_sha256"]}); code != 503 {
		t.Fatal("controller handoff must pause instead of revoking")
	}
	e.mu.Lock()
	e.ctrl = previousController
	e.state = previousState
	e.mu.Unlock()
	if code, _ := post("verify", map[string]any{"token": token, "certificate_sha256": prepared["certificate_sha256"]}); code != 200 {
		t.Fatal("ticket did not recover with the same authority")
	}
	if code, _ := post("close", map[string]any{"token": token}); code != 200 {
		t.Fatal("close failed")
	}
	if code, _ := post("verify", map[string]any{"token": token, "certificate_sha256": prepared["certificate_sha256"]}); code != 403 {
		t.Fatal("closed ticket remained usable")
	}
	_, prepared = post("prepare", map[string]any{"device_key": key.String()})
	c.Disconnect()
	if code, _ := post("verify", map[string]any{"token": prepared["token"], "certificate_sha256": prepared["certificate_sha256"]}); code != 403 {
		t.Fatal("VPN disconnect did not revoke RDP")
	}
}
