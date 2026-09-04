package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

// ACLPolicy is a meshnet's access-control document — a small Tailscale-style
// model: named groups + accept rules over src/dst selectors. It compiles (via
// MemPolicy) into the first isolation layer: which peers appear in each node's
// netmap. Node-side packet filtering (defense in depth, with ports) lands in a
// follow-up (MESH.5b).
//
// Selectors (in src/dst and group members) name MACHINES, never ports:
//   - "*"            any node in the meshnet
//   - "<node-name>"  a node by its registered name
//   - "tag:<name>"   any node carrying that tag
//   - "group:<name>" any member of that group (src/dst only; members are
//     node-names or tags, not nested groups)
//
// Ports live in the rule's own Ports field, not glued onto a dst selector.
// ACLRule for why, and parsePortSpec for the spellings.
//
// LEGACY FORMS still READ (docs stored before the split; rejected on write,
// ValidateACLPolicy): a dst selector could carry a ":<port>" suffix, and
// "svc:<name>" could appear in dst to mean "every node declaring that service,
// on whatever port it declared".
type ACLPolicy struct {
	Groups map[string][]string `json:"groups"`
	ACLs   []ACLRule           `json:"acls"`
}

// ACLRule is one accept rule: every Src machine may reach every Dst machine on
// Ports. v0 supports action "accept" only (there is no deny; absence of an
// allowing rule is denial, and rules are a union — order never matters).
//
// Ports is RULE-level rather than per-dst-selector on purpose. Two reasons:
//
//  1. A rule's src×dst is already a cartesian product; letting each dst selector
//     carry its own port made one row mean several unrelated things at once
//     ("tag:web" next to "svc:db" opened ALL ports on one and one port on the
//     other, looking identical in the console).
//  2. A bare selector used to mean "every port" silently. Making ports an
//     explicit field means opening everything is something an admin TYPES.
//
// A "svc:<name>" entry in Ports resolves against the RECEIVING node's own
// declared services — so the machines are chosen by an admin (Dst) and only the
// port number comes from the device's declaration. Service names are declared
// per-device and are unique only within a device (see core/service.go), so they
// are not a fleet-wide grouping key and must not decide membership: that is what
// tags are for.
type ACLRule struct {
	Action string   `json:"action"`
	Src    []string `json:"src"`
	Dst    []string `json:"dst"`
	// Ports is empty only in legacy documents, where the ports came from the dst
	// selectors themselves. Every newly saved rule has at least one entry.
	Ports []string `json:"ports,omitempty"`
}

// LoadACLPolicy reads a JSON ACL document from path.
func LoadACLPolicy(path string) (*ACLPolicy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("core: read acl policy %s: %w", path, err)
	}
	var p ACLPolicy
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("core: parse acl policy %s: %w", path, err)
	}
	return &p, nil
}

// MemPolicy is a PolicyStore backed by a single in-memory ACLPolicy — the
// self-hosted coordinator's policy source (loaded from a file; the platform build
// swaps a per-org DB-backed policy in MESH.8). It is deployment-agnostic and lives
// in core so the self-hosted coordinator ships the real engine.
type MemPolicy struct{ Policy ACLPolicy }

// Filter returns the subset of candidates self is allowed to see: a peer is
// visible if self may reach it OR it may reach self (both ends must learn each
// other's key for a WireGuard handshake to complete). An empty ACL list denies
// everything (an explicit policy with no rules = no access) — the allow-all
// default lives in AllowAllPolicy, wired only when no policy file is configured.
func (m MemPolicy) Filter(_ context.Context, _ MeshnetID, self *Node, candidates []*Node) ([]*Node, error) {
	out := make([]*Node, 0, len(candidates))
	for _, p := range candidates {
		if m.canReach(self, p) || m.canReach(p, self) {
			out = append(out, p)
		}
	}
	return out, nil
}

// canReach reports whether some accept rule permits src → dst.
func (m MemPolicy) canReach(src, dst *Node) bool {
	for _, r := range m.Policy.ACLs {
		if !strings.EqualFold(r.Action, "accept") {
			continue
		}
		if matchAny(r.Src, src, m.Policy.Groups) && matchAny(r.Dst, dst, m.Policy.Groups) {
			return true
		}
	}
	return false
}

// matchAny reports whether n matches any selector in sels.
func matchAny(sels []string, n *Node, groups map[string][]string) bool {
	for _, s := range sels {
		if matchSelector(s, n, groups) {
			return true
		}
	}
	return false
}

// matchSelector matches one selector against a node. A dst selector may carry a
// ":port" suffix, which the netmap layer ignores (ports are enforced by the
// node-side filter in MESH.5b) — the host part is what is matched here.
func matchSelector(sel string, n *Node, groups map[string][]string) bool {
	sel = stripSelectorPort(strings.TrimSpace(sel))
	switch {
	case sel == "*":
		return true
	case strings.HasPrefix(sel, "group:"):
		for _, member := range groups[sel] {
			if member == n.Name || hasTag(n, member) {
				return true
			}
		}
		return false
	case strings.HasPrefix(sel, "tag:"):
		return hasTag(n, sel)
	case strings.HasPrefix(sel, "svc:"):
		return hasService(n, strings.TrimPrefix(sel, "svc:"))
	default:
		return sel == n.Name
	}
}

// stripSelectorPort removes a trailing ":<digits>" from a selector, whatever its
// prefix. The previous rule ("strip after the last colon unless the selector
// starts with tag:/group:") silently BROKE those prefixed forms: "tag:server:22"
// kept its port and then matched no tag at all — a rule that looked like it
// granted access granted nothing. Deciding on the SUFFIX rather than the prefix
// handles every form: "db:5432", "tag:server:22", "svc:web:443".
func stripSelectorPort(sel string) string {
	i := strings.LastIndexByte(sel, ':')
	if i <= 0 || i == len(sel)-1 {
		return sel
	}
	for _, r := range sel[i+1:] {
		if r < '0' || r > '9' {
			return sel // not a port — e.g. the ":" that introduces tag:/svc:/group:
		}
	}
	return sel[:i]
}

// hasService reports whether the node declares a service by that name. Names are
// normalized labels, so the comparison is exact.
func hasService(n *Node, name string) bool {
	for _, s := range n.Services {
		if s.Name == name {
			return true
		}
	}
	return false
}

func hasTag(n *Node, tag string) bool {
	for _, t := range n.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// ReloadablePolicy is a PolicyStore whose ACL document can be hot-swapped at
// runtime (the coordinator watches the policy file and calls Set on change,
// then re-pushes netmaps). Concurrency-safe: Filter runs on netmap-serving
// goroutines while Set runs on the watcher goroutine.
type ReloadablePolicy struct {
	mu     sync.RWMutex
	policy ACLPolicy
}

// NewReloadablePolicy seeds a reloadable policy with p.
func NewReloadablePolicy(p ACLPolicy) *ReloadablePolicy {
	return &ReloadablePolicy{policy: p}
}

// Set atomically replaces the active policy.
func (r *ReloadablePolicy) Set(p ACLPolicy) {
	r.mu.Lock()
	r.policy = p
	r.mu.Unlock()
}

// Filter evaluates against the current policy snapshot.
func (r *ReloadablePolicy) Filter(ctx context.Context, t MeshnetID, self *Node, candidates []*Node) ([]*Node, error) {
	r.mu.RLock()
	p := r.policy
	r.mu.RUnlock()
	return MemPolicy{Policy: p}.Filter(ctx, t, self, candidates)
}
