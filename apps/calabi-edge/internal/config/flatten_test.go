package config

import (
	"strings"
	"testing"
)

// The tunnel listeners are configured by PORT now, and where this node can be
// reached is one setting. What used to be `control.addr: ":7443"` said "port"
// while looking like "address", and sat among the settings that really are
// addresses; and the port in `public.addr` repeated the one in `control.addr`
// with nothing comparing them.

func TestListenerAddrsBecomePorts(t *testing.T) {
	cfg, err := writeCfg(t, `
node_label: lax-1
public:
  host: edge.example
tunnel:
  base_domain: lax.example
  control:
    addr: ":7443"
  http:
    addr: ":80"
  https:
    addr: ":443"
    self_signed: true
  sni:
    addr: ":8443"
`)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	switch {
	case cfg.Tunnel.ControlPort != 7443:
		t.Errorf("control_port = %d", cfg.Tunnel.ControlPort)
	case cfg.Tunnel.HTTPPort != 80 || cfg.Tunnel.HTTPSPort != 443 || cfg.Tunnel.SNIPort != 8443:
		t.Errorf("ports = %d / %d / %d", cfg.Tunnel.HTTPPort, cfg.Tunnel.HTTPSPort, cfg.Tunnel.SNIPort)
	case !cfg.Tunnel.HTTPSSelfSigned:
		t.Error("https.self_signed did not survive the move to https_self_signed")
	case cfg.Tunnel.ControlAddr() != ":7443":
		t.Errorf("ControlAddr() = %q", cfg.Tunnel.ControlAddr())
	}
}

// An empty addr turned a listener off. So does no port — the same thing said
// the new way, which is what keeps an upgrade from quietly opening :443 on a
// node that had HTTPS off.
func TestAnEmptyAddrStillMeansOff(t *testing.T) {
	cfg, err := writeCfg(t, "node_label: a\npublic:\n  host: a.example\ntunnel:\n  https:\n    addr: \"\"\n  sni:\n    addr: \"\"\n")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Tunnel.HTTPSPort != 0 || cfg.Tunnel.SNIPort != 0 {
		t.Fatalf("https=%d sni=%d, want both off", cfg.Tunnel.HTTPSPort, cfg.Tunnel.SNIPort)
	}
	if cfg.Tunnel.HTTPSAddr() != "" || cfg.Tunnel.SNIAddr() != "" {
		t.Errorf("addrs = %q / %q, want empty", cfg.Tunnel.HTTPSAddr(), cfg.Tunnel.SNIAddr())
	}
}

// The one thing this shape cannot express, refused rather than dropped. A file
// that bound a specific interface has to be rewritten by a person: silently
// binding every interface instead would widen what the node listens on.
func TestABindHostCannotBeExpressedAndIsRefused(t *testing.T) {
	_, err := writeCfg(t, "node_label: a\ntunnel:\n  control:\n    addr: \"10.0.0.5:7443\"\n")
	if err == nil {
		t.Fatal("a bind address with a host was silently turned into a port")
	}
	for _, want := range []string{"10.0.0.5", "control_port"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error should name %q: %v", want, err)
		}
	}
}

// ":7443" and "0.0.0.0:7443" say the same thing, and both are expressible.
func TestBindingEverythingIsExpressible(t *testing.T) {
	for _, addr := range []string{":7443", "0.0.0.0:7443", "[::]:7443"} {
		t.Run(addr, func(t *testing.T) {
			cfg, err := writeCfg(t, "node_label: a\npublic:\n  host: a.example\ntunnel:\n  control:\n    addr: \""+addr+"\"\n")
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if cfg.Tunnel.ControlPort != 7443 {
				t.Errorf("control_port = %d", cfg.Tunnel.ControlPort)
			}
		})
	}
}

func TestPublicAddrBecomesHost(t *testing.T) {
	cfg, err := writeCfg(t, "node_label: a\npublic:\n  addr: \"edge01-sgp.calabi.net:7443\"\ntunnel:\n  control:\n    addr: \":7443\"\n")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Public.Host != "edge01-sgp.calabi.net" {
		t.Errorf("public.host = %q", cfg.Public.Host)
	}
	if got := cfg.AdvertisedAddr(); got != "edge01-sgp.calabi.net:7443" {
		t.Errorf("AdvertisedAddr() = %q", got)
	}
}

// The port used to be written twice and nothing compared them; this migration
// is the last place it can disagree, so it is the last place that check exists.
func TestAnAdvertisedPortThatDisagreesIsRefused(t *testing.T) {
	_, err := writeCfg(t, "node_label: a\npublic:\n  addr: \"edge.example:7444\"\ntunnel:\n  control:\n    addr: \":7443\"\n")
	if err == nil {
		t.Fatal("a node advertising a port it does not bind was accepted")
	}
	for _, want := range []string{"7443", "7444", "public.host"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error should name %q: %v", want, err)
		}
	}
}

func TestPublicAddrWithNoHostIsRefused(t *testing.T) {
	if _, err := writeCfg(t, "node_label: a\npublic:\n  addr: \":7443\"\n"); err == nil {
		t.Fatal("public.addr with no host was accepted; it is what clients dial")
	}
}

// Both spellings in one file: refuse, never pick — the operator is mid-edit and
// the two are exactly the values that will differ.
func TestBothSpellingsOfOnePortAreRefused(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"control", "tunnel:\n  control_port: 7443\n  control:\n    addr: \":7444\"\n", "control_port"},
		{"base domain", "tunnel:\n  base_domain: a.example\n  http:\n    base_domain: b.example\n", "base_domain"},
		{"public", "public:\n  host: a.example\n  addr: \"b.example:7443\"\n", "public.host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := writeCfg(t, "node_label: a\n"+tc.body)
			if err == nil {
				t.Fatal("a file that says one setting twice was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the error should name %q: %v", tc.want, err)
			}
		})
	}
}

// Saying the same thing twice is not ambiguous, and refusing it would fail an
// upgrade for no reason.
func TestAgreeingSpellingsAreAccepted(t *testing.T) {
	cfg, err := writeCfg(t, "node_label: a\npublic:\n  host: a.example\n  addr: \"a.example:7443\"\n"+
		"tunnel:\n  control_port: 7443\n  control:\n    addr: \":7443\"\n")
	if err != nil {
		t.Fatalf("agreeing spellings were refused: %v", err)
	}
	if cfg.Public.Host != "a.example" || cfg.Tunnel.ControlPort != 7443 {
		t.Errorf("got host %q port %d", cfg.Public.Host, cfg.Tunnel.ControlPort)
	}
}

// http.base_domain was the same setting under a second name, kept equal by a
// reconciliation step. It folds in now, and the step is gone.
func TestHTTPBaseDomainFoldsIn(t *testing.T) {
	cfg, err := writeCfg(t, "node_label: a\npublic:\n  host: a.example\ntunnel:\n  http:\n    base_domain: nested.example\n")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Tunnel.BaseDomain != "nested.example" {
		t.Errorf("base_domain = %q", cfg.Tunnel.BaseDomain)
	}
}

// A node that serves tunnels has to say where it can be reached. It used to be
// optional, with public.addr falling back to the control listener's BIND
// address: on one machine ":7443" happens to work as a dial string, which is how
// that fallback survived, and anywhere else it registered the node as reachable
// at an address nothing could reach.
func TestPublicHostIsRequiredOfATunnelNode(t *testing.T) {
	_, err := loadEffectiveYAML(t, "node_label: a\nmode: standalone\ncoord_pubkey: "+testCoordKey+"\n")
	if err == nil {
		t.Fatal("a tunnel node with nowhere to be reached started")
	}
	if !strings.Contains(err.Error(), "public.host") {
		t.Errorf("the error should name public.host: %v", err)
	}
}

// Not required of a relay: it is found through the coordinator's DERP map, which
// names it there. The platform path still warns when it is missing.
func TestPublicHostIsNotRequiredOfARelay(t *testing.T) {
	cfg, err := loadEffectiveYAML(t, "node_label: r1\nregion: hk\nrole: mesh\nmode: standalone\ncoord_pubkey: "+testCoordKey+"\n")
	if err != nil {
		t.Fatalf("a relay with no public.host was refused: %v", err)
	}
	if cfg.AdvertisedAddr() != "" {
		t.Errorf("AdvertisedAddr() = %q, want empty", cfg.AdvertisedAddr())
	}
}

// Somebody upgrading has `control:` at the top level and reads that it is
// `control_port` now. They will write `control_port` at the top level. Without
// the movedKeys entries that lands nowhere and the node silently uses the
// default port — which is the shape of failure this whole file exists to stop.
func TestTheFlatSpellingsAlsoMoveUnderTunnel(t *testing.T) {
	cfg, err := writeCfg(t, "node_label: a\npublic:\n  host: a.example\n"+
		"base_domain: a.example\ncontrol_port: 7444\nhttp_port: 8081\nhttps_port: 0\nsni_port: 9443\n"+
		"control_cert_pem: /etc/calabi/c.crt\ncontrol_key_pem: /etc/calabi/c.key\nhttps_self_signed: true\n")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	switch {
	case cfg.Tunnel.ControlPort != 7444:
		t.Errorf("control_port = %d, want 7444 — it stayed at the top level and was ignored", cfg.Tunnel.ControlPort)
	case cfg.Tunnel.HTTPPort != 8081 || cfg.Tunnel.SNIPort != 9443:
		t.Errorf("http=%d sni=%d", cfg.Tunnel.HTTPPort, cfg.Tunnel.SNIPort)
	case cfg.Tunnel.HTTPSPort != 0:
		t.Errorf("https_port = %d, want it off", cfg.Tunnel.HTTPSPort)
	case cfg.Tunnel.ControlCertPEM != "/etc/calabi/c.crt" || cfg.Tunnel.ControlKeyPEM != "/etc/calabi/c.key":
		t.Errorf("cert = %q / %q", cfg.Tunnel.ControlCertPEM, cfg.Tunnel.ControlKeyPEM)
	case !cfg.Tunnel.HTTPSSelfSigned:
		t.Error("https_self_signed did not move")
	}
}
