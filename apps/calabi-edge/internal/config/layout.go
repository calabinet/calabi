package config

// layout.go — the 2.0.0 config layout, and how a file written for the old one
// still loads.
//
// The edge grew into two services. The config never split with it: `control:`,
// `http:`, `relay:` and the rest all sat at the top, so nothing in a file said
// which of them a given node would even read. A relay-only config looked like
// an edge's. The layout now follows the services — `tunnel:` for what only
// tunnels read, `mesh:` for what only the relay reads, top level for what both
// (or neither) read.
//
// Every key that moved still loads from where it was, and this file is the only
// place that knows it did. The alternative — an alias field per setting, or a
// second parse per block — is the shape this codebase has been burned by
// repeatedly: a whitelist someone forgets to extend, failing open and silent.
// One table, applied to the YAML document before anything is decoded, cannot
// disagree with itself, and a missing entry is a parse error rather than a
// setting that quietly stops working.

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// movedKeys maps a pre-1.15 TOP-LEVEL key to the block it now lives under.
//
// Adding a key here is the whole migration for it. Removing one is not
// backwards compatible and never should be: these spellings are in files on
// machines we do not control.
var movedKeys = map[string]string{
	"base_domain":  "tunnel",
	"control":      "tunnel",
	"http":         "tunnel",
	"https":        "tunnel",
	"sni":          "tunnel",
	"peer_forward": "tunnel",
	// The 2.0.0 flat spellings, for a file written by analogy: somebody who had
	// `control:` at the top level and reads that it is `control_port` now will
	// put `control_port` at the top level. Without these it would land nowhere
	// and the node would silently use the default port.
	"control_port":      "tunnel",
	"control_cert_pem":  "tunnel",
	"control_key_pem":   "tunnel",
	"http_port":         "tunnel",
	"https_port":        "tunnel",
	"https_self_signed": "tunnel",
	"sni_port":          "tunnel",
}

// renamedKeys are settings that kept their place and changed their name, plus
// the two that moved the other way — out of a block and up to the top, because
// both services read them. "<block>.<key>" or "<key>" → "<key>".
//
// These run BEFORE movedKeys, and have to: `tunnel.edge_node_id` must leave the
// old tunnel: block before that key becomes the tunnel SERVICE block.
//
// `cert.org_id` was here for one release, renamed to a top-level `org_id`. Both
// spellings are now refused instead (see deadScalars / deadFields): a node's org
// comes from its certificate, so there is nothing left to rename it to.
var renamedKeys = map[string]string{
	"relay":               "mesh", // the whole block: role mesh's settings
	"tunnel.edge_node_id": "edge_node_id",
	"node_id":             "node_label",
}

// deadBlocks are top-level blocks the edge stopped reading when the direct-dial
// path to the control plane was removed (F3 step 2b). Everything in them is
// inert, so a file that still carries one is a file whose operator believes
// something untrue about where this edge gets its answers.
var deadBlocks = map[string]string{
	"identity":   "the edge reaches identity-svc through bff-edge",
	"quota":      "the edge reaches quota-svc through bff-edge",
	"config_svc": "the edge reaches config-svc through bff-edge",
	"nats":       "the edge subscribes through bff-edge, never to NATS directly",
}

// deadScalars are dead settings that are plain top-level values rather than
// blocks. Same treatment, different shape.
var deadScalars = map[string]string{
	"edge_class": "the routing pool is the control plane's to set, not this node's",
	"org_id":     orgIDIsFromTheCert,
}

// orgIDIsFromTheCert is the one reason, shared by both spellings org_id ever had.
//
// A BYOI node's certificate carries its org in a SPIFFE SAN, and bff-edge stamps
// that org onto everything the node says regardless — the config value could
// never win, only disagree. A PLATFORM node's certificate carries no org because
// it serves every one of them, and it now asks for every one of them (all_orgs);
// until that existed it had to name a single org here and quietly served only
// that org's certificates.
const orgIDIsFromTheCert = "a node's organization comes from its own mTLS certificate; " +
	"a platform node serves every organization and no longer names one"

// deadFields are the same removal, for blocks that also carry live settings and
// therefore survive. Checked on the OLD paths, before anything moves.
var deadFields = map[string]string{
	"tunnel.addr": "the edge reaches tunnel-svc through bff-edge",
	"cert.addr":   "the edge reaches cert-svc through bff-edge",
	// Knobs nobody ever turned. Both had a default and a clamp, neither was set
	// in a single deployed config, and each one still had to be carried through
	// every change to this file. They are refused rather than ignored for the
	// usual reason: an operator who wrote one would otherwise believe they had
	// changed a cadence they had not.
	"tunnel.edge_class":         "the routing pool is the control plane's to set, not this node's",
	"presence.interval_seconds": "the heartbeat cadence is fixed at 15s",
	"cert.refresh_seconds":      "the certificate cache refresh is the client default",
	"cert.org_id":               orgIDIsFromTheCert,
}

// migrateLayout rewrites an old-layout document into the current one, in place,
// and refuses a document that cannot be rewritten unambiguously.
//
// It runs on the YAML node tree before any decoding, so everything downstream —
// the strict-ish decode, the role guard, the hot-reload comparison, the
// obsolete-field check — sees one layout and needs to know nothing about the
// other.
func migrateLayout(doc *yaml.Node) error {
	root := mappingOf(doc)
	if root == nil {
		return nil // empty or scalar document; Load's decode reports it
	}
	if err := rejectRetiredMeshBlock(root); err != nil {
		return err
	}
	if err := rejectDeadBlocks(root); err != nil {
		return err
	}
	// Renames first: they pull keys OUT of blocks that the move below then
	// fills. `tunnel.edge_node_id` is the clearest case — it has to leave the
	// old tunnel: block before that block becomes the tunnel SERVICE block.
	for from, to := range renamedKeys {
		if err := renameKey(root, from, to); err != nil {
			return err
		}
	}
	if err := moveTopLevelKeys(root); err != nil {
		return err
	}
	// Both generations arrive at moveTopLevelKeys' output in the same shape, so
	// the 2.0.0 flattening runs once, after it. See flatten.go.
	if err := flattenTunnelBlock(root); err != nil {
		return err
	}
	return publicAddrToHost(root)
}

// rejectRetiredMeshBlock catches the one collision this layout creates.
//
// `mesh:` used to configure edge-to-edge forwarding of TUNNEL traffic — it
// was never about the mesh, which is why it is now `tunnel.peer_forward:`. The
// same key is now the mesh SERVICE block. Reading an old one as the new one
// would take a node out of its region's peer-forwarding pool and configure a
// relay that was never asked for, in silence.
//
// It is refused rather than migrated because the two cannot be told apart
// reliably enough to bet a production node on a guess, and because this
// spelling never shipped: it appears only in configs we deploy ourselves, never
// in the published bundle or in any documentation.
func rejectRetiredMeshBlock(root *yaml.Node) error {
	m := mappingOf(childOf(root, "mesh"))
	if m == nil {
		return nil
	}
	for _, k := range []string{"forward_addr", "advertise_addr"} {
		if childOf(m, k) != nil {
			return fmt.Errorf("config has mesh.%s, which is edge-to-edge forwarding of TUNNEL traffic (M15) "+
				"and has nothing to do with the mesh — `mesh:` now configures the mesh relay. Rename that "+
				"block to tunnel.peer_forward:", k)
		}
	}
	return nil
}

func rejectDeadBlocks(root *yaml.Node) error {
	var dead []string
	for k, why := range deadBlocks {
		n := childOf(root, k)
		if n == nil {
			continue
		}
		// An empty block is how a file says "none"; it misleads nobody.
		if m := mappingOf(n); m != nil && len(m.Content) == 0 {
			continue
		}
		dead = append(dead, fmt.Sprintf("%s (%s)", k, why))
	}
	for k, why := range deadScalars {
		if v := childOf(root, k); v != nil && strings.TrimSpace(v.Value) != "" {
			dead = append(dead, fmt.Sprintf("%s (%s)", k, why))
		}
	}
	for path, why := range deadFields {
		block, key, _ := strings.Cut(path, ".")
		if v := childOf(mappingOf(childOf(root, block)), key); v != nil && strings.TrimSpace(v.Value) != "" {
			dead = append(dead, fmt.Sprintf("%s (%s)", path, why))
		}
	}
	if len(dead) == 0 {
		return nil
	}
	sort.Strings(dead)
	// The reason in brackets is per setting, because they no longer share one.
	// Most of these died when the edge stopped dialing the control plane
	// directly; the rest are answers that were never this node's to give.
	return fmt.Errorf("config sets %s. None of them does anything — remove them. If this edge "+
		"reaches a control plane it does so through multi_region (mode: bff-edge, bff_edge_addr, "+
		"client_cert, client_key, ca), which also tells it who it is; if it runs without one, "+
		"set mode: standalone", strings.Join(dead, ", "))
}

// renameKey moves one key to its new name, refusing a document that spells it
// both ways with different values. from is "key" or "block.key".
func renameKey(root *yaml.Node, from, to string) error {
	parent := root
	name := from
	if block, key, nested := strings.Cut(from, "."); nested {
		parent = mappingOf(childOf(root, block))
		name = key
		if parent == nil {
			return nil
		}
	}
	old := childOf(parent, name)
	if old == nil {
		return nil
	}
	if cur := childOf(root, to); cur != nil {
		if !sameScalar(cur, old) {
			if cur.Kind == yaml.MappingNode || old.Kind == yaml.MappingNode {
				return fmt.Errorf("config sets both %s: and %s: — %s: was renamed to %s: in 2.0.0, "+
					"so this file configures it twice. Keep the %s: one", from, to, from, to, to)
			}
			return fmt.Errorf("config: %s (%s) and %s (%s) disagree; set one of them",
				to, cur.Value, from, old.Value)
		}
		deleteKey(parent, name)
		return nil
	}
	deleteKey(parent, name)
	setKey(root, to, old)
	return nil
}

// moveTopLevelKeys nests every movedKeys entry under its block.
func moveTopLevelKeys(root *yaml.Node) error {
	// Sorted, so a document with several conflicts always names the same one.
	keys := make([]string, 0, len(movedKeys))
	for k := range movedKeys {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		block := movedKeys[key]
		old := childOf(root, key)
		if old == nil {
			continue
		}
		dest := mappingOf(childOf(root, block))
		if dest == nil {
			deleteKey(root, key)
			setKey(root, block, newMapping(key, old))
			continue
		}
		// Both layouts in one file. Refuse rather than pick: the operator is
		// mid-migration and the two almost certainly differ.
		if childOf(dest, key) != nil {
			return fmt.Errorf("config sets both %s: and %s.%s: — the top-level spelling moved under %s: "+
				"in 2.0.0, so this file says it twice. Keep the %s.%s: one",
				key, block, key, block, block, key)
		}
		deleteKey(root, key)
		setKey(dest, key, old)
	}
	return nil
}

// --- yaml.Node helpers -------------------------------------------------------
//
// yaml.v3 mappings are a flat []*Node of alternating key, value. Nothing in the
// library indexes them, so these four do.

func mappingOf(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		n = n.Content[0]
	}
	if n.Kind != yaml.MappingNode {
		return nil
	}
	return n
}

func childOf(parent *yaml.Node, key string) *yaml.Node {
	m := mappingOf(parent)
	if m == nil {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func deleteKey(parent *yaml.Node, key string) {
	m := mappingOf(parent)
	if m == nil {
		return
	}
	kept := m.Content[:0]
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			continue
		}
		kept = append(kept, m.Content[i], m.Content[i+1])
	}
	m.Content = kept
}

func setKey(parent *yaml.Node, key string, val *yaml.Node) {
	m := mappingOf(parent)
	if m == nil {
		return
	}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, val)
}

func newMapping(key string, val *yaml.Node) *yaml.Node {
	return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, val,
	}}
}

// sameScalar: two spellings of one setting agree. Non-scalars never do — a
// block written twice is not something to merge behind the operator's back.
func sameScalar(a, b *yaml.Node) bool {
	return a.Kind == yaml.ScalarNode && b.Kind == yaml.ScalarNode &&
		strings.EqualFold(strings.TrimSpace(a.Value), strings.TrimSpace(b.Value))
}
