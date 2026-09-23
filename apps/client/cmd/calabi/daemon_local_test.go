package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	proto "github.com/calabinet/calabi/pkg/protocol"
)

// testPinA is a well-formed certificate pin for configs that need one.
const testPinA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestLoadLocalConfig_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "calabi.yaml")
	yaml := `mesh:
  coord: coord.example.com:7012
  trust: pin
  pins: [` + testPinA + `]
tunnels:
  - name: web
    type: http
    local: 8080
    domain: app.example.com
  - name: ssh
    type: tcp
    local: 127.0.0.1:22
    remote_port: 2222
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadLocalConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Mesh.Coord != "coord.example.com:7012" || cfg.Mesh.Enabled || len(cfg.Mesh.Pins) != 1 {
		t.Errorf("mesh block wrong: %+v", cfg.Mesh)
	}
	if len(cfg.Tunnels) != 2 {
		t.Fatalf("want 2 tunnels, got %d", len(cfg.Tunnels))
	}
	if cfg.Tunnels[1].Type != "tcp" || cfg.Tunnels[1].RemotePort != 2222 {
		t.Errorf("tcp tunnel wrong: %+v", cfg.Tunnels[1])
	}
}

// The settings that named the edge are gone: the coordinator names it. A
// hand-written file that still sets them is refused, naming them and the way
// in, instead of either failing on "unknown field" or appearing to still use
// them; the console's own file has them set aside (the daemon rewrites it).
func TestLoadLocalConfig_RemovedEdgeSettings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "calabi.yaml")
	body := "server: edge.example.com:7443\ntoken: s3cret\ntrust: pin\npins: [" + testPinA + "]\n" +
		"mesh:\n  coord: coord.example.com:7012\n  trust: pin\n  pins: [" + testPinA + "]\n" +
		"tunnels:\n  - name: web\n    type: http\n    local: 8080\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := loadLocalConfig(path)
	if err == nil {
		t.Fatal("a hand-written config that names the edge loaded")
	}
	for _, want := range []string{"server", "token", "trust", "pins", "calabi join"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal should name %q: %v", want, err)
		}
	}
	if !strings.Contains(err.Error(), "server, token, trust, pins") {
		t.Errorf("the refusal should list exactly the top-level settings, in file order: %v", err)
	}

	cfg, removed, err := loadLocalConfigOrEmpty(path, true)
	if err != nil {
		t.Fatalf("the console's own file must load with them set aside: %v", err)
	}
	if strings.Join(removed, ",") != "server,token,trust,pins" {
		t.Errorf("set aside %v, want server,token,trust,pins", removed)
	}
	// The mesh block's own trust and pins are the coordinator's, not the edge's.
	if cfg.Mesh.Coord != "coord.example.com:7012" || cfg.Mesh.Trust != "pin" || len(cfg.Mesh.Pins) != 1 || len(cfg.Tunnels) != 1 {
		t.Errorf("the rest of the file did not survive: %+v", cfg)
	}

	if _, removed, err := loadLocalConfigOrEmpty(path, false); err == nil || removed != nil {
		t.Errorf("a hand-written file (managed=false) must be refused: removed=%v err=%v", removed, err)
	}
}

// The example the help text and the self-hosting docs point at is a config the
// client accepts, every tunnel in it included. It went stale once already: it
// named the edge and a token after the client stopped reading either.
func TestTheExampleConfigLoads(t *testing.T) {
	cfg, err := loadLocalConfig(filepath.Join("..", "..", "..", "..", "docs", "examples", "calabi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mesh.Coord == "" {
		t.Error("the example joins no coordinator: nothing would name its edge")
	}
	if _, err := cfg.Mesh.coordTrust(cfg.Mesh.AuthKey); err != nil {
		t.Errorf("the example's coordinator trust: %v", err)
	}
	var logs strings.Builder
	planned := planTunnels(slog.New(slog.NewTextHandler(&logs, nil)), cfg.Tunnels)
	if len(planned) != len(cfg.Tunnels) || len(planned) == 0 {
		t.Errorf("planned %d of %d tunnels:\n%s", len(planned), len(cfg.Tunnels), logs.String())
	}
}

// Unknown fields must error (KnownFields strict) so a typo'd policy key doesn't
// silently disable protection.
func TestLoadLocalConfig_UnknownFieldErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("tunnels:\n  - name: x\n    typ: http\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadLocalConfig(path); err == nil {
		t.Fatal("want error for unknown field `typ`, got nil")
	}
}

// An http tunnel's basic-auth password must be bcrypt-hashed into the
// config_json — never carried in cleartext.
func TestToSessionTunnel_BasicAuthHashedNotCleartext(t *testing.T) {
	tc := localTunnelConfig{
		Name:  "web",
		Type:  "http",
		Local: "8080",
		Security: &localSecurityConfig{
			IPAllow:   []string{"10.0.0.0/8"},
			BasicAuth: []string{"admin:hunter2"},
		},
	}
	tun, err := toSessionTunnel(tc)
	if err != nil {
		t.Fatalf("toSessionTunnel: %v", err)
	}
	if tun.Type != proto.ProxyKindHTTP {
		t.Errorf("type = %v, want http", tun.Type)
	}
	if tun.LocalAddr != "127.0.0.1:8080" {
		t.Errorf("local = %q, want 127.0.0.1:8080", tun.LocalAddr)
	}
	blob := tun.SecurityConfigJSON
	if !strings.Contains(blob, `"user":"admin"`) {
		t.Errorf("missing user in blob: %s", blob)
	}
	if !strings.Contains(blob, `"hash":"$2`) {
		t.Errorf("password not bcrypt-hashed in blob: %s", blob)
	}
	if strings.Contains(blob, "hunter2") {
		t.Fatalf("cleartext password leaked into config_json: %s", blob)
	}
	if !strings.Contains(blob, `"allow":["10.0.0.0/8"]`) {
		t.Errorf("ip allow missing: %s", blob)
	}
}

// HTTP-only knobs on a non-http tunnel must be rejected, not silently dropped.
func TestToSessionTunnel_L4RejectsHTTPOnlySecurity(t *testing.T) {
	tc := localTunnelConfig{
		Name:  "ssh",
		Type:  "tcp",
		Local: "127.0.0.1:22",
		Security: &localSecurityConfig{
			BasicAuth: []string{"a:b"},
		},
	}
	if _, err := toSessionTunnel(tc); err == nil {
		t.Fatal("want error for basic_auth on a tcp tunnel, got nil")
	}
}

// L4 tunnels accept IP policy from YAML (present in every deployment).
func TestToSessionTunnel_L4AcceptsIP(t *testing.T) {
	tc := localTunnelConfig{
		Name:       "ssh",
		Type:       "tcp",
		Local:      "127.0.0.1:22",
		RemotePort: 2222,
		Security:   &localSecurityConfig{IPDeny: []string{"1.2.3.4"}},
	}
	tun, err := toSessionTunnel(tc)
	if err != nil {
		t.Fatalf("toSessionTunnel: %v", err)
	}
	if !strings.Contains(tun.SecurityConfigJSON, `"deny":["1.2.3.4"]`) {
		t.Errorf("ip policy wrong: %s", tun.SecurityConfigJSON)
	}
}

func TestParseProxyKind(t *testing.T) {
	cases := map[string]proto.ProxyKind{
		"http": proto.ProxyKindHTTP,
		"TCP":  proto.ProxyKindTCP,
		" udp": proto.ProxyKindUDP,
		"sni":  proto.ProxyKindSNI,
	}
	for in, want := range cases {
		got, err := parseProxyKind(in)
		if err != nil || got != want {
			t.Errorf("parseProxyKind(%q) = (%v,%v), want %v", in, got, err, want)
		}
	}
	if _, err := parseProxyKind("ftp"); err == nil {
		t.Error("want error for unknown type ftp")
	}
}

func TestResolveSubdomainDomain(t *testing.T) {
	cases := []struct {
		name, domain, subdomain, base, want string
	}{
		{"prefix+base", "", "myapp", "localtest.me", "myapp.localtest.me"},
		{"explicit domain wins", "app.example.com", "myapp", "localtest.me", "app.example.com"},
		{"prefix lowercased+trimmed", "", "  MyApp ", "localtest.me", "myapp.localtest.me"},
		{"no base → auto", "", "myapp", "", ""},
		{"no subdomain → auto", "", "", "localtest.me", ""},
		{"nothing → auto", "", "", "", ""},
	}
	for _, c := range cases {
		if got := resolveSubdomainDomain(c.domain, c.subdomain, c.base); got != c.want {
			t.Errorf("%s: resolveSubdomainDomain(%q,%q,%q) = %q, want %q",
				c.name, c.domain, c.subdomain, c.base, got, c.want)
		}
	}
}

func TestToSessionTunnel_CarriesSubdomain(t *testing.T) {
	tun, err := toSessionTunnel(localTunnelConfig{
		Type: "http", Local: "8080", Subdomain: "  MyApp ",
	})
	if err != nil {
		t.Fatalf("toSessionTunnel: %v", err)
	}
	if tun.Subdomain != "myapp" {
		t.Errorf("Subdomain = %q, want normalized %q", tun.Subdomain, "myapp")
	}
}

func TestValidateLocalUpstream(t *testing.T) {
	// Hermetic cases only — no real DNS. localhost + *.local are accepted
	// without a lookup; IP literals are checked directly.
	ok := []string{
		"", "127.0.0.1:8080", "8080", "localhost:3000",
		"10.0.0.5:80", "192.168.1.50:8080", "172.16.0.1:443",
		"[::1]:8080", "169.254.1.1:80", "0.0.0.0:8080", "nas.local:445",
	}
	for _, a := range ok {
		if err := validateLocalUpstream(a); err != nil {
			t.Errorf("validateLocalUpstream(%q) = %v, want nil", a, err)
		}
	}
	// Missing / invalid port → rejected before any DNS lookup. "www.google.com"
	// (the reported bug) lands here: no port.
	badFormat := []string{"www.google.com", "myhost", "127.0.0.1:", "host:abc"}
	for _, a := range badFormat {
		if err := validateLocalUpstream(a); err == nil {
			t.Errorf("validateLocalUpstream(%q) = nil, want error (bad host:port)", a)
		}
	}
	// Public IP literals → rejected.
	badPublic := []string{"1.2.3.4:80", "8.8.8.8:53", "203.0.113.10:8080"}
	for _, a := range badPublic {
		if err := validateLocalUpstream(a); err == nil {
			t.Errorf("validateLocalUpstream(%q) = nil, want error (public IP)", a)
		}
	}
}

func TestNormalizeLocalAddr(t *testing.T) {
	if got := normalizeLocalAddr("8080"); got != "127.0.0.1:8080" {
		t.Errorf("bare port = %q, want 127.0.0.1:8080", got)
	}
	if got := normalizeLocalAddr("0.0.0.0:9000"); got != "0.0.0.0:9000" {
		t.Errorf("host:port should pass through, got %q", got)
	}
	if got := normalizeLocalAddr(""); got != "" {
		t.Errorf("empty should stay empty, got %q", got)
	}
	// A hostname with no port must NOT become "127.0.0.1:<hostname>" (the
	// www.google.com bug) — it's left as-is for validation to reject.
	if got := normalizeLocalAddr("www.google.com"); got != "www.google.com" {
		t.Errorf("hostname w/o port = %q, want unchanged www.google.com", got)
	}
}

func TestDaemonIsLocal_Flag(t *testing.T) {
	// Force a non-standalone client mode so only the flag can trigger local.
	t.Setenv("CALABI_MODE", "platform")
	if !daemonIsLocal([]string{"--local", "--config", "x.yaml"}) {
		t.Error("--local should select the local daemon")
	}
	if daemonIsLocal([]string{"--name", "d"}) {
		t.Error("no --local + platform mode should NOT select the local daemon")
	}
}

func TestDaemonIsLocal_StandaloneMode(t *testing.T) {
	t.Setenv("CALABI_MODE", "standalone")
	if !daemonIsLocal([]string{"--config", "x.yaml"}) {
		t.Error("standalone client mode should select the local daemon even without --local")
	}
}
