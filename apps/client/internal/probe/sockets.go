package probe

// Socket enumeration: the LISTENing TCP sockets on this machine, each with the
// address it is actually BOUND to (0.0.0.0, 127.0.0.1, a specific IP, ...).
//
// Why this exists next to the dial scan in ports.go, when that already answers
// "is something on this port": the dial scan can only tell listening from not,
// and only for the curated port list. It cannot see the ONE thing the operator
// keeps getting wrong — the bind address. A service on 127.0.0.1 dials fine from
// this box and is unreachable from every mesh peer, and the only way to know
// which it is, without a second machine, is to read the bind address off the
// kernel's own socket table. Enumeration also finds ports the curated list never
// guessed.
//
// This stays on :7400 and NEVER rides to the coordinator. That is the whole
// distinction of the console UX plan draws: enumerating listeners and then
// REPORTING them to the control plane would hand it a per-machine attack-surface
// map, which is vetoed; enumerating them for the person sitting at this machine,
// where the data never leaves the host, is exactly the alternative keeps.
// What crosses the wire is still only what the operator DECLARES.
//
// Enumeration is best-effort. When the platform has no table we can read (or the
// read fails), listenerSockets returns errEnumUnsupported and Scan falls back to
// the dial probe — a strictly weaker view, but never a broken page.

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
)

// errEnumUnsupported means this build has no socket-table reader; the caller
// falls back to the dial scan.
var errEnumUnsupported = errors.New("probe: socket enumeration not supported on this platform")

// listener is one LISTENing TCP socket. ip is the bound address; an unspecified
// ip (0.0.0.0 or ::) means a wildcard bind (every interface). Implemented per
// platform (sockets_{linux,windows,darwin}.go); the stub returns
// errEnumUnsupported.
type listener struct {
	ip   netip.Addr
	port int
}

// Scan is the entry point behind /v1/probe/ports. It prefers real enumeration
// (which carries the bind address and covers every port) and falls back to the
// dial probe when the platform can't be enumerated, so the page always renders.
//
// overlay is this machine's mesh address, or "" when it isn't on the mesh — in
// which case reachability is left unprobed rather than reported as false.
func Scan(ctx context.Context, overlay string) []PortInfo {
	socks, err := listenerSockets()
	if err != nil {
		// No table to read: fall back to dialing the curated list. Label the rows
		// so the UI (and anyone reading the JSON) knows this is the weaker view
		// with no bind address to show.
		rows := Ports(ctx, overlay)
		for i := range rows {
			rows[i].Source = "dialed"
		}
		return rows
	}
	return scanFrom(ctx, socks, overlay)
}

// scanFrom turns a raw listener set into UI rows: one row per port, the distinct
// bind addresses gathered onto it, and — when this machine is on the mesh — a
// reachability verdict.
//
// Reachability is still decided by an actual dial of the overlay address, the
// same ground truth the dial path uses, rather than inferred from the bind
// address. The bind address answers "what is it bound to"; the dial answers
// "can a peer reach it", and keeping them as two independent signals means the
// enumerated view can never DISAGREE with what a peer would actually experience
// (dual-stack "::" binds, v6-only sockets and the like are where inference goes
// wrong). The dial stays on this host — the overlay address is local — so
// nothing leaves the machine here either.
func scanFrom(ctx context.Context, socks []listener, overlay string) []PortInfo {
	byPort := map[int]*PortInfo{}
	binds := map[int][]netip.Addr{}
	var order []int
	for _, s := range socks {
		pi := byPort[s.port]
		if pi == nil {
			pi = &PortInfo{Port: s.port, Listening: true, Hint: hintFor(s.port), Source: "enumerated"}
			byPort[s.port] = pi
			order = append(order, s.port)
		}
		binds[s.port] = appendAddr(binds[s.port], s.ip)
	}

	out := make([]PortInfo, 0, len(order))
	for _, p := range order {
		pi := byPort[p]
		for _, b := range binds[p] {
			pi.BindAddrs = append(pi.BindAddrs, b.String())
		}
		out = append(out, *pi)
	}

	if overlay != "" {
		probeMeshReach(ctx, out, overlay)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

// probeMeshReach dials each row's port on the overlay address, in parallel, to
// separate "bound so a peer can reach it" from "bound to loopback only". Mirrors
// the fan-out in Ports so a slow port can't stall the sweep.
func probeMeshReach(ctx context.Context, rows []PortInfo, overlay string) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)
	for i := range rows {
		i := i
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			rows[i].MeshProbed = true
			rows[i].MeshReachable = dialOK(ctx, net.JoinHostPort(overlay, strconv.Itoa(rows[i].Port)))
		}()
	}
	wg.Wait()
}

// appendAddr adds ip to addrs unless an equal one is already present, so a port
// bound several times on the same address shows it once.
func appendAddr(addrs []netip.Addr, ip netip.Addr) []netip.Addr {
	for _, a := range addrs {
		if a == ip {
			return addrs
		}
	}
	return append(addrs, ip)
}
