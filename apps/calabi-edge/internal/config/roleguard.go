package config

import (
	"fmt"
	"strings"
)

// roleguard.go — the two startup assertions that make `role: relay` a claim the
// operator can VERIFY, now that the standalone derp-node binary is retired.
//
// Retiring that binary traded a process boundary for a config flag. The
// isolation itself is unchanged where it matters — a relay-only node still
// binds no TLS-terminating listener, and pkg/relay still links no edge code
// (pkg/relay/deps_test.go proves that at the package level) — but "I am only a
// relay" went from something you could see in the process list to something you
// have to trust a config field for. These two checks give it back:
//
//   - RelayOnlyIsExplicit: a relay-only node may not carry tunnel listener
//     settings. If it does, the operator believes something about this node
//     that is not true, and we say so instead of silently ignoring them.
//   - RoleMatchesRelayBlock: writing a relay: block without role: relay
//     silently produces an EDGE (empty role defaults to edge). Refuse to guess.
//
// Both take the RAW parse — the zero-valued second unmarshal Load already does —
// so they can tell "the operator wrote this" from "Default() filled it in".

// checkRoleConfig runs both assertions. cfg is the merged config (defaults
// applied); raw is the same YAML parsed over a zero Config, so a non-empty
// field in raw means the file actually said so.
func checkRoleConfig(cfg Config, raw Config) error {
	if err := roleMatchesRelayBlock(raw); err != nil {
		return err
	}
	return relayOnlyIsExplicit(cfg, raw)
}

// roleMatchesRelayBlock refuses a config that configures a relay but never says
// role: relay. Empty role means "edge" (RunsEdge returns true for ""), so such
// a file starts a tunnel ingress that ignores the whole relay block — the
// operator gets neither the relay they wrote nor an error telling them why.
func roleMatchesRelayBlock(raw Config) error {
	if strings.TrimSpace(raw.Role) != "" {
		return nil // the operator stated a role; ValidateRole checks it is real
	}
	if raw.Relay == (RelayRole{}) {
		return nil // no relay block, nothing to disambiguate
	}
	return fmt.Errorf("config has a relay: block but no role: — an empty role means \"edge\", " +
		"so this node would serve tunnels and ignore the relay settings entirely. " +
		"Set role: relay (relay only) or role: both (tunnels + relay)")
}

// relayOnlyIsExplicit refuses tunnel listener settings on a relay-only node.
//
// Those listeners are never bound when RunsEdge() is false, so today they are
// merely inert — but inert-and-ignored is exactly the state in which someone
// concludes "this box also serves HTTP" from reading its config. A relay-only
// node's config should describe a relay-only node.
func relayOnlyIsExplicit(cfg Config, raw Config) error {
	if !cfg.RunsRelay() || cfg.RunsEdge() {
		return nil // not relay-only
	}
	var set []string
	for _, f := range []struct {
		name string
		val  string
	}{
		{"control.addr", raw.Control.Addr},
		{"http.addr", raw.HTTP.Addr},
		{"https.addr", raw.HTTPS.Addr},
		{"sni.addr", raw.SNI.Addr},
		{"mesh.forward_addr", raw.Mesh.ForwardAddr},
	} {
		if strings.TrimSpace(f.val) != "" {
			set = append(set, f.name)
		}
	}
	if len(set) == 0 {
		return nil
	}
	return fmt.Errorf("role: relay serves NO tunnels, but this config sets tunnel listener(s): %s. "+
		"A relay-only node binds only the relay data port and the STUN responder — it never terminates "+
		"TLS. Remove those settings, or use role: both if this node really should serve tunnels too",
		strings.Join(set, ", "))
}
