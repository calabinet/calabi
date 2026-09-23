package config

// flatten.go — the 1.16 shape of `tunnel:` and `public:`, and how a file
// written for the old one still loads.
//
// Every tunnel listener was configured by an `addr`, and in every config ever
// deployed the host half of that addr was empty: `control.addr: ":7443"`. They
// had to be — all four listeners must be reachable from outside the machine, so
// there was never a host to choose. What they actually named was a port, while
// looking exactly like the four settings that ARE addresses (public, admin,
// peer_forward.advertise_addr, multi_region.bff_edge_addr). Nine settings ending
// in `addr`, four of them addresses.
//
// So: where this node can be reached is ONE setting, `public.host`, and each
// service names the port it wants — which is what `mesh:` already did with
// derp_port / stun_port. The port that used to be written into public.addr AND
// into control.addr, with nothing comparing them, is now written once.
//
// This runs after moveTopLevelKeys, so both generations arrive here in the same
// shape: whether the file said `control:` at the top (pre-1.15) or under
// `tunnel:` (1.15), by now it is `tunnel.control.addr`.

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// portFields map a block-and-key under `tunnel:` to the flat port key that
// replaces it. The VALUE is rewritten too: ":7443" becomes 7443.
var portFields = map[string]string{
	"control.addr": "control_port",
	"http.addr":    "http_port",
	"https.addr":   "https_port",
	"sni.addr":     "sni_port",
}

// flatFields are the rest of what those blocks held: same value, new place.
//
// `http.base_domain` folds into `base_domain` rather than moving beside it. It
// was the same setting under two names, kept equal by a reconciliation step
// that now has nothing to reconcile.
var flatFields = map[string]string{
	"control.cert_pem":  "control_cert_pem",
	"control.key_pem":   "control_key_pem",
	"https.self_signed": "https_self_signed",
	"http.base_domain":  "base_domain",
}

// flattenTunnelBlock rewrites tunnel.<block>.<key> into tunnel.<flat_key>.
func flattenTunnelBlock(root *yaml.Node) error {
	tunnel := mappingOf(childOf(root, "tunnel"))
	if tunnel == nil {
		return nil
	}
	// Sorted, so a file with several conflicts always names the same one.
	paths := make([]string, 0, len(portFields)+len(flatFields))
	for k := range portFields {
		paths = append(paths, k)
	}
	for k := range flatFields {
		paths = append(paths, k)
	}
	sort.Strings(paths)

	for _, path := range paths {
		blockName, key, _ := strings.Cut(path, ".")
		block := mappingOf(childOf(tunnel, blockName))
		if block == nil {
			continue
		}
		old := childOf(block, key)
		if old == nil {
			continue
		}
		flat, isPort := portFields[path]
		if !isPort {
			flat = flatFields[path]
		}
		val := old
		if isPort {
			port, err := portOfBindAddr(old.Value)
			if err != nil {
				return fmt.Errorf("tunnel.%s: %w. It is a port now (tunnel.%s), and this node "+
					"publishes one address of its own — public.host", path, err, flat)
			}
			// An empty addr turned the listener off, and it did so by OVERWRITING
			// the default the decode starts from. So it becomes an explicit 0,
			// not a deleted key: dropping the key would leave Default()'s port in
			// place and open a listener the file had switched off.
			val = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(port)}
		}
		if cur := childOf(tunnel, flat); cur != nil {
			if !sameScalar(cur, val) {
				return fmt.Errorf("config sets both tunnel.%s: and tunnel.%s: — %s was replaced by %s "+
					"in 1.16, so this file says it twice. Keep the %s: one", path, flat, path, flat, flat)
			}
			deleteKey(block, key)
			continue
		}
		deleteKey(block, key)
		setKey(tunnel, flat, val)
	}
	// Drop the husks, so a strict reader never sees `control: {}`.
	for _, blockName := range []string{"control", "http", "https", "sni"} {
		if b := mappingOf(childOf(tunnel, blockName)); b != nil && len(b.Content) == 0 {
			deleteKey(tunnel, blockName)
		}
	}
	return nil
}

// publicAddrToHost turns `public.addr: "host:port"` into `public.host: "host"`,
// and refuses a file whose port disagrees with the listener it is supposed to
// name.
//
// That check exists only here, and only for the length of this migration: after
// it the port is written once, so there is nothing left to disagree. Which is
// the better version of the check — a reconciliation you delete beats one you
// maintain.
func publicAddrToHost(root *yaml.Node) error {
	pub := mappingOf(childOf(root, "public"))
	if pub == nil {
		return nil
	}
	addr := childOf(pub, "addr")
	if addr == nil {
		return nil
	}
	host, port := splitHostPortLoose(strings.TrimSpace(addr.Value))
	if host == "" {
		return fmt.Errorf("public.addr %q names no host. It is the address clients dial, so it needs "+
			"a name or IP that reaches this node from outside it — and it is spelled public.host now, "+
			"without a port", addr.Value)
	}
	if port != "" {
		if ctrl := childOf(mappingOf(childOf(root, "tunnel")), "control_port"); ctrl != nil &&
			strings.TrimSpace(ctrl.Value) != port {
			return fmt.Errorf("public.addr advertises port %s but the control listener binds %s. "+
				"Clients dial the advertised one, so they would arrive at a port this node is not "+
				"listening on. The port is written once now: keep tunnel.control_port and spell this "+
				"one public.host: %s", port, ctrl.Value, host)
		}
	}
	if cur := childOf(pub, "host"); cur != nil {
		if strings.TrimSpace(cur.Value) != host {
			return fmt.Errorf("config sets both public.addr: (%q) and public.host: (%q); keep public.host",
				addr.Value, cur.Value)
		}
		deleteKey(pub, "addr")
		return nil
	}
	deleteKey(pub, "addr")
	setKey(pub, "host", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: host})
	return nil
}

// portOfBindAddr reads the port out of a listener's old bind address. An empty
// addr is 0 — "off", which is what it meant. A host that is not "everything"
// cannot be expressed any more and is refused rather than dropped.
func portOfBindAddr(addr string) (int, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return 0, nil
	}
	host, port := splitHostPortLoose(addr)
	if port == "" {
		return 0, fmt.Errorf("%q has no port", addr)
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
	default:
		return 0, fmt.Errorf("%q binds the host %q, which cannot be written any more", addr, host)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n <= 0 || n > 65535 {
		return 0, fmt.Errorf("%q has no usable port", addr)
	}
	return n, nil
}

// splitHostPortLoose splits "host:port", "[v6]:port", a bare host, or a
// port-only bind address like ":7443". Anything it cannot split is taken to be
// a bare host, which is how the relay registrar has always read public.addr.
func splitHostPortLoose(s string) (host, port string) {
	if s == "" {
		return "", ""
	}
	if i := strings.LastIndex(s, ":"); i >= 0 && !strings.Contains(s[i+1:], "]") {
		h, p := s[:i], s[i+1:]
		if _, err := strconv.Atoi(p); err == nil {
			return strings.Trim(h, "[]"), p
		}
	}
	return s, ""
}
