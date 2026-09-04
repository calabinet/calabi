package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// env.go — environment overrides for the settings a CONFIG-FILE-LESS node needs.
//
// Why: retiring the standalone derp-node
// binary removed a program whose entire configuration was environment
// variables. Its selling point for self-hosters was "no domain, no certificate,
// no config file — just run it". A relay-only edge has exactly the same needs,
// so the knobs a pure relay uses are readable from the environment too; without
// this, retiring derp-node would have forced every self-hosted relay to start
// mounting a YAML file it otherwise has no use for.
//
// Scope is deliberately narrow: mode, role, and the relay block. Everything an
// EDGE needs (listeners, certificates, base domain, control-plane addresses)
// stays file-driven — those configs are large, and half-env/half-file is how
// deployments become unexplainable.
//
// Precedence: environment WINS over the file. An operator reaching for an env
// var is overriding something, usually from a container orchestrator.

// ApplyEnv overlays the supported environment variables onto cfg and returns
// it. Unset variables change nothing. A malformed value is an error rather than
// a silent fallback: a relay that ignored REQUIRE_AUTH because of a typo would
// be exactly the fail-open posture prodguard.go exists to prevent.
func ApplyEnv(cfg Config) (Config, error) {
	if v := envStr("CALABI_EDGE_MODE"); v != "" {
		cfg.Mode = v
	}
	if v := envStr("CALABI_EDGE_ROLE"); v != "" {
		cfg.Role = v
	}
	// A second edge-image container on the SAME host (the self-hosted stack runs
	// the edge and the relay side by side under host networking) would otherwise
	// fight the first one for the default admin port :9101. The retired derp-node
	// avoided this by using :9200; this is how a relay-only node does it now.
	if v := envStr("CALABI_EDGE_ADMIN_ADDR"); v != "" {
		cfg.Admin.Addr = v
	}
	if v := envStr("CALABI_EDGE_RELAY_KIND"); v != "" {
		cfg.Relay.Kind = v
	}
	if v := envStr("CALABI_EDGE_RELAY_LABEL"); v != "" {
		cfg.Relay.Label = v
	}
	if v := envStr("CALABI_EDGE_RELAY_COORD_PUBKEY"); v != "" {
		cfg.Relay.CoordPubKey = v
	}
	if v := envStr("CALABI_EDGE_RELAY_DERP_PORT"); v != "" {
		n, err := parsePort("CALABI_EDGE_RELAY_DERP_PORT", v)
		if err != nil {
			return cfg, err
		}
		cfg.Relay.DERPPort = n
	}
	if v := envStr("CALABI_EDGE_RELAY_STUN_PORT"); v != "" {
		n, err := parsePort("CALABI_EDGE_RELAY_STUN_PORT", v)
		if err != nil {
			return cfg, err
		}
		cfg.Relay.STUNPort = n
	}
	if v := envStr("CALABI_EDGE_RELAY_REQUIRE_AUTH"); v != "" {
		b, err := parseBool("CALABI_EDGE_RELAY_REQUIRE_AUTH", v)
		if err != nil {
			return cfg, err
		}
		cfg.Relay.RequireAuth = b
	}
	return cfg, nil
}

func envStr(key string) string { return strings.TrimSpace(os.Getenv(key)) }

// parsePort accepts a bare port number. 0 is legal — it disables the STUN
// responder — so only negative and non-numeric values are rejected.
func parsePort(key, raw string) (int, error) {
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 || n > 65535 {
		return 0, fmt.Errorf("%s=%q is not a port number (0-65535)", key, raw)
	}
	return n, nil
}

func parseBool(key, raw string) (bool, error) {
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	}
	return false, fmt.Errorf("%s=%q is not a boolean (1/0, true/false, yes/no, on/off)", key, raw)
}
