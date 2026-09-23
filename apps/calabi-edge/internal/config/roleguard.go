package config

import (
	"fmt"
	"strconv"
	"strings"
)

// roleguard.go — the two startup assertions that make `role: mesh` a claim the
// operator can VERIFY, now that the standalone derp-node binary is retired.
//
// Retiring that binary traded a process boundary for a config flag. The
// isolation itself is unchanged where it matters — a relay-only node still
// binds no TLS-terminating listener, and pkg/relay still links no edge code
// (pkg/relay/deps_test.go proves that at the package level) — but "I am only a
// relay" went from something you could see in the process list to something you
// have to trust a config field for. These two checks give it back:
//
//   - RelayOnlyIsExplicit: a mesh-only node may not carry tunnel listener
//     settings. If it does, the operator believes something about this node
//     that is not true, and we say so instead of silently ignoring them.
//   - RoleMatchesRelayBlock: writing a relay: block without role: mesh
//     silently produces a TUNNEL node (empty role defaults to tunnel). Refuse
//     to guess.
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
// role: mesh. Empty role means tunnels (ServesTunnels returns true for ""), so
// such a file starts a tunnel ingress that ignores the whole relay block — the
// operator gets neither the relay they wrote nor an error telling them why.
func roleMatchesRelayBlock(raw Config) error {
	if strings.TrimSpace(raw.Role) != "" {
		return nil // the operator stated a role; ValidateRole checks it is real
	}
	if raw.Mesh == (MeshService{}) {
		return nil // no relay block, nothing to disambiguate
	}
	return fmt.Errorf("config has a relay: block but no role: — an empty role means \"tunnel\", " +
		"so this node would serve tunnels and ignore the relay settings entirely. " +
		"Set role: mesh (the mesh relay only) or role: both (tunnels + mesh)")
}

// relayOnlyIsExplicit refuses tunnel listener settings on a relay-only node.
//
// Those listeners are never bound when ServesTunnels() is false, so today they are
// merely inert — but inert-and-ignored is exactly the state in which someone
// concludes "this box also serves HTTP" from reading its config. A relay-only
// node's config should describe a relay-only node.
func relayOnlyIsExplicit(cfg Config, raw Config) error {
	if !cfg.ServesMesh() || cfg.ServesTunnels() {
		return nil // not relay-only
	}
	var set []string
	for _, f := range []struct {
		name string
		val  string
	}{
		{"control_port", portText(raw.Tunnel.ControlPort)},
		// The control listener's server certificate. A mesh relay terminates no
		// TLS at all — it forwards ciphertext it cannot read,
		// runRelay takes only the mesh block, and pkg/relay names no TLS type.
		// So these belong to the tunnel and nowhere else, and a mesh-only config
		// that sets them describes a node that does not exist.
		{"control_cert_pem", raw.Tunnel.ControlCertPEM},
		{"control_key_pem", raw.Tunnel.ControlKeyPEM},
		{"http_port", portText(raw.Tunnel.HTTPPort)},
		{"https_port", portText(raw.Tunnel.HTTPSPort)},
		{"sni_port", portText(raw.Tunnel.SNIPort)},
		{"peer_forward.forward_addr", raw.Tunnel.PeerForward.ForwardAddr},
	} {
		if strings.TrimSpace(f.val) != "" {
			set = append(set, f.name)
		}
	}
	if len(set) == 0 {
		return nil
	}
	return fmt.Errorf("role: mesh serves NO tunnels, but this config sets tunnel listener(s): %s. "+
		"A mesh-only node binds only the relay data port and the STUN responder — it never terminates "+
		"TLS. Remove those settings, or use role: both if this node really should serve tunnels too",
		strings.Join(set, ", "))
}

// portText renders a port for the "is this set" check above. Zero is unset,
// which is also how a port turns its listener off.
func portText(port int) string {
	if port <= 0 {
		return ""
	}
	return strconv.Itoa(port)
}
