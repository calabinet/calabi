package config

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// deploy/server is the bundle every self-hoster starts from: one compose file
// that writes the edge's YAML from environment variables. Nothing checked that
// the YAML it writes parses — it was validated by somebody running it, which
// means a typo in it ships and is found by a stranger.
//
// It is also the file most likely to be left behind by a config change, because
// it is not a.yaml anyone greps: the config lives inside a heredoc inside a
// shell command inside the compose file.

var bundleEnv = map[string]string{
	"CALABI_NODE_NAME":     "calabi-server",
	"CALABI_PUBLIC_HOST":   "server.example.com",
	"CALABI_TUNNEL_DOMAIN": "tunnels.example.com",
}

func TestTheSelfHostedBundlesEdgeConfigLoads(t *testing.T) {
	compose, err := os.ReadFile("../../../../deploy/server/docker-compose.yml")
	if err != nil {
		t.Fatalf("the published bundle is not where this test looks: %v", err)
	}
	body := edgeYAMLFromCompose(t, string(compose))

	clearCalabiEnv(t)
	p := writeTemp(t, body)
	cfg, notes, err := LoadEffective(p)
	if err != nil {
		t.Fatalf("the bundle writes a config the edge refuses:\n%s\n\n%v", body, err)
	}

	// Spot-check what the bundle is FOR, so a config that parses but configures
	// nothing cannot pass.
	switch {
	case !cfg.ServesTunnels() || !cfg.ServesMesh():
		t.Errorf("role = %q, want both services", cfg.Role)
	case !cfg.IsStandaloneMode():
		t.Errorf("mode = %q, want standalone", cfg.Mode)
	case cfg.Public.Host != bundleEnv["CALABI_PUBLIC_HOST"]:
		t.Errorf("public.host = %q — the bundle tells the coordinator this host and must tell the edge too", cfg.Public.Host)
	case cfg.Tunnel.ControlPort == 0:
		t.Error("no control port: no client could connect")
	case cfg.AdvertisedAddr() == "":
		t.Error("nothing to advertise: the edge directory would get an empty address")
	case cfg.Mesh.RelayDERPPort() == 0:
		t.Error("no relay port")
	case cfg.CoordPubKeyFile == "":
		t.Error("no coordinator key: the edge would admit nobody")
	}
	for _, w := range notes.Warnings {
		t.Errorf("the bundle should need no warning at boot: %s", w)
	}
}

// The coordinator is told the edge's dial address, and the edge composes its
// own from public.host + tunnel.control_port. Two places, one answer — this is
// the check that they agree, because nothing else compares them.
func TestTheBundleTellsCoordinatorAndEdgeTheSameAddress(t *testing.T) {
	compose, err := os.ReadFile("../../../../deploy/server/docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`CALABI_COORD_EDGE_ADDR:\s*(\S+)`).FindStringSubmatch(string(compose))
	if m == nil {
		t.Fatal("the bundle no longer tells the coordinator where the edge is")
	}
	coordSide := expandBundleEnv(m[1])

	clearCalabiEnv(t)
	p := writeTemp(t, edgeYAMLFromCompose(t, string(compose)))
	cfg, _, err := LoadEffective(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.AdvertisedAddr(); got != coordSide {
		t.Errorf("the coordinator is told %q and the edge advertises %q", coordSide, got)
	}
}

// edgeYAMLFromCompose pulls the edge's config out of the heredoc the bundle
// writes it with, and fills in the environment the operator supplies.
func edgeYAMLFromCompose(t *testing.T, compose string) string {
	t.Helper()
	const open = "cat > /tmp/edge.yaml <<'EOF'\n"
	i := strings.Index(compose, open)
	if i < 0 {
		t.Fatal("the bundle no longer writes /tmp/edge.yaml with a heredoc; teach this test the new shape")
	}
	rest := compose[i+len(open):]
	j := strings.Index(rest, "\n        EOF")
	if j < 0 {
		t.Fatal("unterminated heredoc in the bundle")
	}
	var out []string
	for _, line := range strings.Split(rest[:j], "\n") {
		out = append(out, strings.TrimPrefix(line, "        "))
	}
	return expandBundleEnv(strings.Join(out, "\n") + "\n")
}

// expandBundleEnv resolves ${VAR} and ${VAR:-default} the way compose would.
func expandBundleEnv(s string) string {
	return regexp.MustCompile(`\$\{([A-Z_]+)(:-[^}]*)?\}`).ReplaceAllStringFunc(s, func(m string) string {
		g := regexp.MustCompile(`\$\{([A-Z_]+)(?::-([^}]*))?\}`).FindStringSubmatch(m)
		if v, ok := bundleEnv[g[1]]; ok {
			return v
		}
		return g[2]
	})
}

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	p := t.TempDir() + "/edge.yaml"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}
