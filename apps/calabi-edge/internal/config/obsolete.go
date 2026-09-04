package config

import (
	"fmt"
	"strings"
)

// obsolete.go — refuse settings that no longer do anything.
//
// F3 step 2b removed the edge's direct-dial path: every edge reaches the
// control plane through bff-edge, and the code that dialed identity-svc /
// tunnel-svc / cert-svc / quota-svc / config-svc by address is gone. The
// config FIELDS survive because their structs carry live settings too
// (cert.org_id, tunnel.edge_node_id), so a stale `identity.addr:` in a YAML
// would now parse fine and mean nothing.
//
// Silently ignoring it is the failure mode this codebase keeps running into:
// a config nobody enforces is a config someone reads and believes. An operator
// who sees identity.addr in their file concludes this edge talks to
// identity-svc — and would be wrong in a way that matters, because what
// actually happens is authentication falls back to the static accepted_tokens
// table. So: name the dead setting and say what replaced it.

// checkObsoleteFields rejects direct-dial addresses. raw is the zero-valued
// parse Load already does, so this fires only on settings the FILE carries —
// never on anything Default() filled in.
func checkObsoleteFields(raw Config) error {
	var dead []string
	for _, f := range []struct {
		name string
		val  string
	}{
		{"identity.addr", raw.Identity.Addr},
		{"tunnel.addr", raw.Tunnel.Addr},
		{"cert.addr", raw.Cert.Addr},
		{"quota.addr", raw.Quota.Addr},
		{"config_svc.addr", raw.Config.Addr},
	} {
		if strings.TrimSpace(f.val) != "" {
			dead = append(dead, f.name)
		}
	}
	if len(dead) == 0 {
		return nil
	}
	return fmt.Errorf("config sets %s, which no longer does anything: the edge reaches the control plane "+
		"only through bff-edge now, so these direct-dial addresses are dead settings. Remove them and "+
		"configure multi_region (mode: bff-edge, bff_edge_addr, client_cert, client_key, ca) — or set "+
		"mode: standalone if this edge is meant to run without a control plane",
		strings.Join(dead, ", "))
}
