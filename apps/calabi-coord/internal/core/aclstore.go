package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ACLStore holds one ACL document per meshnet — the SaaS per-org policy the
// console editor reads and writes (MESH.8e-2). meshnet == org, so this is the
// org's access-control document. The platform build backs it with a DB table
// (mesh_acls, calabi-coord-owned); the community build leaves it nil (its single
// ACL comes from a file — see cmd/calabi-coord/policy.go). A meshnet with no
// stored doc is "not found" and treated as allow-all by ACLFilter.
type ACLStore interface {
	// GetACL returns the meshnet's ACL doc and whether one is stored. A missing
	// doc returns (zero, false, nil) — NOT an error.
	GetACL(ctx context.Context, t MeshnetID) (ACLPolicy, bool, error)
	// SetACL stores (creates or replaces) the meshnet's ACL doc.
	SetACL(ctx context.Context, t MeshnetID, p ACLPolicy) error
}

// ErrInvalidACL wraps every ValidateACLPolicy failure at the SaveACL boundary,
// so the HTTP layer can answer 400 (the admin's document is wrong) instead of
// 500 (we are broken) without matching on message text.
var ErrInvalidACL = errors.New("invalid acl document")

// ACLRevision is one saved version of a meshnet's ACL document.
type ACLRevision struct {
	ID        int64     `json:"id"`
	Policy    ACLPolicy `json:"policy"`
	Actor     string    `json:"actor"`
	CreatedAt time.Time `json:"created_at"`
}

// ACLRevisionStore keeps the history of a meshnet's ACL documents. Editing
// access rules is the most dangerous action in the console (a wrong doc cuts
// every node at once), so every save is appended and a previous version can be
// put back. Optional: a coordinator without one still edits ACLs, just without
// history.
type ACLRevisionStore interface {
	// AppendRevision records a saved document. actor is who saved it as the BFF
	// knows them (e.g. "user:42"), or "" when unattributed.
	AppendRevision(ctx context.Context, t MeshnetID, p ACLPolicy, actor string) error
	// ListRevisions returns a meshnet's revisions, newest first, capped at limit.
	ListRevisions(ctx context.Context, t MeshnetID, limit int) ([]ACLRevision, error)
}

// MemACLRevisionStore is an in-memory ACLRevisionStore (dev / tests / community).
type MemACLRevisionStore struct {
	mu   sync.RWMutex
	next int64
	m    map[MeshnetID][]ACLRevision
}

func NewMemACLRevisionStore() *MemACLRevisionStore {
	return &MemACLRevisionStore{m: map[MeshnetID][]ACLRevision{}}
}

func (s *MemACLRevisionStore) AppendRevision(_ context.Context, t MeshnetID, p ACLPolicy, actor string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	// Newest first, mirroring what the store's index returns.
	s.m[t] = append([]ACLRevision{{ID: s.next, Policy: p, Actor: actor, CreatedAt: time.Now()}}, s.m[t]...)
	return nil
}

func (s *MemACLRevisionStore) ListRevisions(_ context.Context, t MeshnetID, limit int) ([]ACLRevision, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	all := s.m[t]
	if limit > 0 && len(all) > limit {
		all = all[:limit]
	}
	return append([]ACLRevision(nil), all...), nil
}

// MemACLStore is an in-memory ACLStore (dev / tests / the platform no-DSN
// fallback). Edition-agnostic — zero control-plane deps.
type MemACLStore struct {
	mu sync.RWMutex
	m  map[MeshnetID]ACLPolicy
}

// NewMemACLStore returns an empty in-memory ACL store.
func NewMemACLStore() *MemACLStore { return &MemACLStore{m: map[MeshnetID]ACLPolicy{}} }

// GetACL returns the stored doc for t, or (zero,false,nil).
func (s *MemACLStore) GetACL(_ context.Context, t MeshnetID) (ACLPolicy, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.m[t]
	return p, ok, nil
}

// SetACL stores p for t.
func (s *MemACLStore) SetACL(_ context.Context, t MeshnetID, p ACLPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[t] = p
	return nil
}

// ACLFilter is a PolicyStore that enforces each meshnet's OWN stored ACL doc,
// falling back to Fallback (allow-all, or the global file policy) when a
// meshnet has no doc. This is the platform's per-org netmap filter (MESH.8e-2).
//
// Read-error posture: if the store read fails, ACLFilter degrades to the
// Fallback default rather than erroring the netmap pull — consistent with the
// codebase's "degrade open, don't wedge the data plane on a control-plane blip"
// stance (cf. the quota gate). ACL here is the netmap-visibility layer; a brief
// window of the fallback default on a transient DB error is preferable to
// cutting a node off from its map entirely.
type ACLFilter struct {
	Store    ACLStore
	Fallback PolicyStore
}

// Filter applies the meshnet's stored doc when present, else the fallback.
func (f ACLFilter) Filter(ctx context.Context, t MeshnetID, self *Node, candidates []*Node) ([]*Node, error) {
	if f.Store != nil {
		if doc, ok, err := f.Store.GetACL(ctx, t); err == nil && ok {
			return MemPolicy{Policy: doc}.Filter(ctx, t, self, candidates)
		}
		// err != nil OR !ok both fall through to the fallback default below.
	}
	if f.Fallback != nil {
		return f.Fallback.Filter(ctx, t, self, candidates)
	}
	// No store doc, no fallback → allow-all (a fresh meshnet is full-mesh until
	// an admin writes rules).
	return candidates, nil
}

// ACL document validation limits (defensive; an admin doc is small in practice).
const (
	maxACLRules       = 500
	maxACLGroups      = 200
	maxACLSelectors   = 200
	maxSelectorLength = 256
)

// ValidateACLPolicy structurally validates an ACL document before it is stored
// (MESH.8e-2 write path). It rejects the shapes MemPolicy would silently ignore
// so an admin gets a clear error instead of a policy that quietly does nothing:
//
//   - only action "accept" is supported (there is no deny; absence = denial)
//   - every rule needs at least one src, one dst and one port
//   - selectors must be non-empty and within length limits
//   - a group:<name> selector must reference a group defined in Groups
//   - a tag:<name> selector must name a non-empty tag
//   - selectors name MACHINES: no ":port" suffix, no "svc:" on either side
//   - every port entry must parse (see parsePortSpec)
//   - group MEMBERS are node-names or tags, never nested group: references
//
// It does NOT check that referenced node-names/tags exist (nodes come and go),
// matching Tailscale — an unmatched name is simply a rule that grants nothing.
//
// It DOES reject a doc with zero rules. That shape is the most dangerous thing
// an editor can produce by accident: there is no deny action, so "no rules" is
// not "no policy" — it is deny-everything, and saving it cuts every node pair in
// the meshnet at once (the write path re-pushes all netmaps immediately). An
// admin who deletes the last rule almost always means "go back to open", which
// is a rule, not the absence of one. Blocking it here covers every caller (both
// BFFs, curl), not just the console's own guard.
func ValidateACLPolicy(p ACLPolicy) error {
	if len(p.ACLs) == 0 {
		return fmt.Errorf(`a policy with no rules denies ALL traffic between nodes: ` +
			`to keep the meshnet open save the rule ` +
			`{"action":"accept","src":["*"],"dst":["*"],"ports":["*"]}, ` +
			`or disable individual nodes instead`)
	}
	if len(p.ACLs) > maxACLRules {
		return fmt.Errorf("too many rules: %d (max %d)", len(p.ACLs), maxACLRules)
	}
	if len(p.Groups) > maxACLGroups {
		return fmt.Errorf("too many groups: %d (max %d)", len(p.Groups), maxACLGroups)
	}
	// Groups: names must be group:-prefixed (matchSelector looks them up by the
	// full "group:x" key); members must be node-names or tags, not nested groups.
	for name, members := range p.Groups {
		if !strings.HasPrefix(name, "group:") || strings.TrimSpace(strings.TrimPrefix(name, "group:")) == "" {
			return fmt.Errorf("group name %q must be of the form group:<name>", name)
		}
		// An all-digit suffix reads as a port to stripSelectorPort, so a selector
		// naming this group would match nothing. Refuse the name rather than let
		// it become a rule that silently grants nothing.
		if stripSelectorPort(name) != name {
			return fmt.Errorf("group name %q ends in digits after a colon, which reads as a port; rename it", name)
		}
		if len(members) > maxACLSelectors {
			return fmt.Errorf("group %q has too many members: %d (max %d)", name, len(members), maxACLSelectors)
		}
		for _, m := range members {
			m = strings.TrimSpace(m)
			if m == "" || len(m) > maxSelectorLength {
				return fmt.Errorf("group %q has an empty or over-long member", name)
			}
			if strings.HasPrefix(m, "group:") {
				return fmt.Errorf("group %q member %q: nested groups are not allowed", name, m)
			}
			if strings.HasPrefix(m, "tag:") && strings.TrimSpace(strings.TrimPrefix(m, "tag:")) == "" {
				return fmt.Errorf("group %q has an empty tag member", name)
			}
		}
	}
	// Rules.
	for i, r := range p.ACLs {
		if !strings.EqualFold(strings.TrimSpace(r.Action), "accept") {
			return fmt.Errorf("rule %d: action %q unsupported (only \"accept\")", i, r.Action)
		}
		if len(r.Src) == 0 || len(r.Dst) == 0 {
			return fmt.Errorf("rule %d: needs at least one src and one dst", i)
		}
		if len(r.Src) > maxACLSelectors || len(r.Dst) > maxACLSelectors {
			return fmt.Errorf("rule %d: too many selectors", i)
		}
		if len(r.Ports) == 0 {
			return fmt.Errorf(`rule %d: needs a "ports" list — ports are no longer written onto dst `+
				`selectors. Use ["*"] for every port, ["5432"] or ["tcp:5432"] for a literal, `+
				`or ["svc:<name>"] for whatever port each destination declared for that service`, i)
		}
		if len(r.Ports) > maxACLSelectors {
			return fmt.Errorf("rule %d: too many ports", i)
		}
		if err := validateSelectors("rule "+itoa(i)+" src", r.Src, p.Groups); err != nil {
			return err
		}
		if err := validateSelectors("rule "+itoa(i)+" dst", r.Dst, p.Groups); err != nil {
			return err
		}
		if err := validatePortSpecs("rule "+itoa(i)+" ports", r.Ports); err != nil {
			return err
		}
	}
	return nil
}

// validatePortSpecs checks a rule's Ports entries against the one parser the
// compiler uses, so nothing can be saved that would silently resolve to no port.
func validatePortSpecs(where string, specs []string) error {
	for _, s := range specs {
		s = strings.TrimSpace(s)
		if s == "" || len(s) > maxSelectorLength {
			return fmt.Errorf("%s: empty or over-long port", where)
		}
		if _, ok := parsePortSpec(s); !ok {
			return fmt.Errorf(`%s: %q is not a port — use "*", "5432", "8000-8100", "tcp:5432" `+
				`or "svc:<service-name>"`, where, s)
		}
	}
	return nil
}

// validateSelectors checks one side of a rule. Both sides answer the SAME
// question now — which machines — so both are checked the same way, and neither
// may carry a port or name a service.
//
// Why "svc:" is refused on BOTH sides, having previously been the way to name a
// destination: a service name is declared by whoever runs the device and is
// unique only within that device (core/service.go). Two people who each call
// their own thing "web" have not formed a group. Letting that name decide
// membership would mean an unprivileged self-declaration widens an existing
// rule — the project's "authorization beats self-report" line, crossed. So the
// name may decide the PORT (rule.Ports) but never WHO is in scope: tag the
// machines and use tag:<name>.
//
// A ":port" suffix is refused for the same reason a source port never was
// enforceable: ports are a field now, and a selector that looks like it
// constrains one would not.
func validateSelectors(where string, sels []string, groups map[string][]string) error {
	for _, s := range sels {
		s = strings.TrimSpace(s)
		if s == "" || len(s) > maxSelectorLength {
			return fmt.Errorf("%s: empty or over-long selector", where)
		}
		if strings.HasPrefix(s, "svc:") {
			return fmt.Errorf(`%s: selector %q — a service name is chosen per-device and is not a `+
				`group of machines, so it cannot select them; put "%s" in the rule's "ports" instead `+
				`and name the machines with tag:<name>`, where, s, s)
		}
		if stripSelectorPort(s) != s {
			return fmt.Errorf(`%s: selector %q carries a port — move it to the rule's "ports" list`, where, s)
		}
		switch {
		case s == "*":
			// any
		case strings.HasPrefix(s, "group:"):
			if _, ok := groups[s]; !ok {
				return fmt.Errorf("%s: selector %q references an undefined group", where, s)
			}
		case strings.HasPrefix(s, "tag:"):
			if strings.TrimSpace(strings.TrimPrefix(s, "tag:")) == "" {
				return fmt.Errorf("%s: empty tag selector", where)
			}
		default:
			// bare node-name; nothing more to validate structurally (an unknown
			// name is allowed — nodes come and go — it simply grants nothing).
		}
	}
	return nil
}

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}
