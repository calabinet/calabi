package core

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Answering "what will this ACL edit actually do?" before it is saved, and
// "why can/can't A reach B?" after it is. Both run the SAME matcher the netmap
// filter runs (MemPolicy), so a preview can't drift from the enforcement — the
// failure mode of a hand-written simulator is that it agrees with the real
// filter right up until the day it matters.
//
// ⚠ Reachability here is the NETMAP layer, which is UNDIRECTED: MemPolicy.Filter
// keeps a peer when self may reach it OR it may reach self, because both ends
// need each other's key for a WireGuard handshake. So a rule "a → b" today opens
// the pair in both directions. Directional (and port-level) enforcement is the
// node-side packet filter's; this check answers for the netmap layer
// and says so explicitly rather than letting an admin believe they wrote a
// one-way rule.

// ReachPair is one node pair whose reachability changed.
type ReachPair struct {
	AID   int64  `json:"a_id"`
	AName string `json:"a_name"`
	BID   int64  `json:"b_id"`
	BName string `json:"b_name"`
}

// ACLDiff is what an edit would change, in node pairs.
type ACLDiff struct {
	Nodes      int         `json:"nodes"`
	TotalPairs int         `json:"total_pairs"`
	Added      []ReachPair `json:"added"`     // newly reachable
	Removed    []ReachPair `json:"removed"`   // cut by this edit
	Unchanged  int         `json:"unchanged"` // pairs whose reachability is untouched
}

// AccessCheck explains one src→dst question against a policy.
type AccessCheck struct {
	SrcName string `json:"src"`
	DstName string `json:"dst"`
	// Forward/Reverse report whether a rule permits that direction, and which
	// rule (index into the doc's acls, -1 when none matched).
	Forward     bool `json:"forward"`
	ForwardRule int  `json:"forward_rule"`
	Reverse     bool `json:"reverse"`
	ReverseRule int  `json:"reverse_rule"`
	// Reachable is the EFFECTIVE answer at the netmap layer: undirected, so
	// either direction matching opens the pair (see the note above).
	Reachable bool `json:"reachable"`
}

// reachable reports whether the pair is mutually visible under p (nil = the
// allow-all default: no stored doc and no policy file).
func reachable(p *ACLPolicy, a, b *Node) bool {
	if p == nil {
		return true
	}
	m := MemPolicy{Policy: *p}
	return m.canReach(a, b) || m.canReach(b, a)
}

// matchingRule returns the index of the first accept rule permitting src→dst,
// or -1. Nil policy = allow-all, reported as rule -1 (there is no document to
// point at).
func matchingRule(p *ACLPolicy, src, dst *Node) int {
	if p == nil {
		return -1
	}
	for i, r := range p.ACLs {
		if !strings.EqualFold(strings.TrimSpace(r.Action), "accept") {
			continue
		}
		if matchAny(r.Src, src, p.Groups) && matchDst(r.Dst, src, dst, p.Groups) {
			return i
		}
	}
	return -1
}

// DiffPolicies reports what changes between two policies over a node set: which
// pairs gain reachability and which LOSE it. `before` nil means the meshnet
// currently runs on the allow-all default (no stored doc, no policy file) — the
// case where the first save is most likely to cut everything by surprise.
//
// Pairs are unordered (i<j) because the netmap layer is undirected. Disabled
// nodes are skipped: they are already out of every netmap, so counting them
// would inflate the "cut" number with connections that don't exist.
func DiffPolicies(nodes []*Node, before *ACLPolicy, after ACLPolicy) ACLDiff {
	active := make([]*Node, 0, len(nodes))
	for _, n := range nodes {
		if n != nil && !n.Disabled {
			active = append(active, n)
		}
	}
	sort.Slice(active, func(i, j int) bool { return active[i].ID < active[j].ID })

	d := ACLDiff{Nodes: len(active)}
	for i := 0; i < len(active); i++ {
		for j := i + 1; j < len(active); j++ {
			a, b := active[i], active[j]
			d.TotalPairs++
			was := reachable(before, a, b)
			now := reachable(&after, a, b)
			switch {
			case was == now:
				d.Unchanged++
			case now:
				d.Added = append(d.Added, pairOf(a, b))
			default:
				d.Removed = append(d.Removed, pairOf(a, b))
			}
		}
	}
	return d
}

func pairOf(a, b *Node) ReachPair {
	return ReachPair{AID: a.ID, AName: a.Name, BID: b.ID, BName: b.Name}
}

// PreviewACL computes what saving `doc` would do to the caller's meshnet. The
// baseline is what the meshnet runs on RIGHT NOW: its stored doc, else the
// policy file, else the allow-all default (see currentPolicy).
func (c *Coordinator) PreviewACL(ctx context.Context, t MeshnetID, doc ACLPolicy) (ACLDiff, error) {
	nodes, err := c.nodesWithServices(ctx, t)
	if err != nil {
		return ACLDiff{}, err
	}
	before, err := c.currentPolicy(ctx, t)
	if err != nil {
		return ACLDiff{}, err
	}
	return DiffPolicies(nodes, before, doc), nil
}

// CheckAccess answers "can src reach dst" for two nodes named in the meshnet.
// doc is the policy to evaluate — pass nil to ask about what is live now.
func (c *Coordinator) CheckAccess(ctx context.Context, t MeshnetID, srcName, dstName string, doc *ACLPolicy) (AccessCheck, error) {
	nodes, err := c.nodesWithServices(ctx, t)
	if err != nil {
		return AccessCheck{}, err
	}
	src := findNodeByName(nodes, srcName)
	dst := findNodeByName(nodes, dstName)
	if src == nil {
		return AccessCheck{}, fmt.Errorf("%w: %q", ErrNodeNotFound, srcName)
	}
	if dst == nil {
		return AccessCheck{}, fmt.Errorf("%w: %q", ErrNodeNotFound, dstName)
	}
	if doc == nil {
		if doc, err = c.currentPolicy(ctx, t); err != nil {
			return AccessCheck{}, err
		}
	}
	fwd := matchingRule(doc, src, dst)
	rev := matchingRule(doc, dst, src)
	return AccessCheck{
		SrcName:     src.Name,
		DstName:     dst.Name,
		Forward:     doc == nil || fwd >= 0,
		ForwardRule: fwd,
		Reverse:     doc == nil || rev >= 0,
		ReverseRule: rev,
		Reachable:   reachable(doc, src, dst),
	}, nil
}

// currentPolicy returns the document the meshnet runs on: its stored doc, else
// the one the netmap filter falls back to (the policy file, when one is
// configured). nil only for the allow-all default. A store read error is an
// error here, not a fallback: a preview that quietly compares against the wrong
// baseline would tell the admin the opposite of the truth, and a packet filter
// compiled from the file could open ports the meshnet's own doc closes.
func (c *Coordinator) currentPolicy(ctx context.Context, t MeshnetID) (*ACLPolicy, error) {
	if c.ACL != nil {
		doc, ok, err := c.ACL.GetACL(ctx, t)
		if err != nil {
			return nil, fmt.Errorf("core: read acl: %w", err)
		}
		if ok {
			return &doc, nil
		}
	}
	return policyDocument(c.Policy)
}

// policyDocument returns the document p enforces for a meshnet with no stored
// doc. nil = allow-all.
//
// It is what keeps the packet filter, the checker and the preview on the SAME
// document the peer list was cut with. They used to read the ACL store alone,
// so a meshnet on CALABI_COORD_POLICY_FILE got the file's peers and an
// allow-all filter: every port open, from everywhere.
//
// A PolicyStore not listed here is an error, not nil. nil compiles to "every
// port from everywhere", so defaulting to it would reopen that hole, silently,
// for whatever policy source is added next.
func policyDocument(p PolicyStore) (*ACLPolicy, error) {
	switch p := p.(type) {
	case nil, AllowAllPolicy:
		return nil, nil
	case ACLFilter:
		// Its store is c.ACL, already read by currentPolicy; what is left is
		// the default it falls back to.
		return policyDocument(p.Fallback)
	case *ReloadablePolicy:
		// Never nil, even when the file failed to load: that is an EMPTY doc
		// (deny-all), and has to stay one here.
		doc := p.Doc()
		return &doc, nil
	case MemPolicy:
		return &p.Policy, nil
	}
	return nil, fmt.Errorf("core: cannot tell which ACL document %T enforces", p)
}

func findNodeByName(nodes []*Node, name string) *Node {
	name = NormalizeNodeName(name)
	for _, n := range nodes {
		if NormalizeNodeName(n.Name) == name {
			return n
		}
	}
	return nil
}
