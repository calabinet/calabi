// Package probe powers the "local diagnostics" surface: which
// ports on this machine look like things the user might want to expose
// as a tunnel, and whether each tunnel's local upstream is actually
// answering right now.
//
// Why a probe package and not a third-party deps (gopsutil)?
//
//   - Binary footprint. The daemon already weighs ~23 MB with the SPA
//     embedded; gopsutil adds another ~5 MB across all platforms for a
//     feature most users never touch.
//   - Permissions. Listing the *owning* process of a socket needs
//     elevated rights on Windows (and we'd rather not nag a desktop
//     daemon for admin token). Showing "port X is listening" without
//     the pid is usually enough — the user knows their own dev stack.
//   - Cross-platform pain. /proc/net on Linux vs. iphlpapi on Windows
//     vs. netstat-shell-out on macOS all behave differently for IPv6
//     vs. dual-stack vs. local-only sockets.
//
// So this package takes a simpler approach: dial-test localhost on a
// curated list of common dev ports (3000, 5000, 8080, ...) plus any
// user-extension via $CALABI_PROBE_PORTS. Anything that accepts the
// connection is "listening" — good enough for "suggest a tunnel here".
package probe

import (
	"context"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Default probe set — the union of frameworks people commonly run
// locally. Kept short on purpose: a full 1-65535 sweep would be
// noticeable on the network if the user's firewall logs.
var defaultPorts = []int{
	22, // ssh — rarely tunneled but flagged so the user knows it's there
	80, 81, 88,
	443, 444, 445,
	1080, 1234, 1313, 1337,
	2375, 2376, 2379, 2380, // docker / etcd
	3000, 3001, 3030, 3306, 3333, 3389, // common dev + mysql + rdp
	4000, 4040, 4200, 4321, 4567,
	5000, 5001, 5050, 5173, 5432, 5500, 5601, 5672, // flask / vite / postgres / kibana / rabbitmq
	6000, 6379, 6443, 6660,
	7000, 7001, 7070, 7077, 7400, 7474, 7878,
	8000, 8001, 8008, 8025, 8080, 8081, 8086, 8088,
	8090, 8125, 8443, 8500, 8761, 8888, 8983,
	9000, 9001, 9090, 9091, 9092, 9200, 9300, 9418, 9999,
	11211, // memcached
	15672, // rabbitmq admin
	27017, // mongodb
	50051, // grpc default
}

// PortInfo is the result row returned to the UI. Listening=true means
// dial succeeded; Latency is the dial duration which roughly correlates
// with whether the socket is being accepted vs. RST'd by a stateful
// firewall.
type PortInfo struct {
	Port      int           `json:"port"`
	Listening bool          `json:"listening"`
	LatencyMs int64         `json:"latency_ms"`
	Hint      string        `json:"hint,omitempty"`
	latency   time.Duration `json:"-"`
	// MeshProbed reports whether we were able to test mesh reachability at all
	// (false when this machine has no overlay address — i.e. it isn't on the
	// mesh). It exists so "we couldn't check" never reads as "not reachable":
	// that distinction is the whole reason this pair of fields is two booleans
	// rather than one.
	MeshProbed bool `json:"mesh_probed"`
	// MeshReachable reports whether the port accepts a connection to this
	// machine's OVERLAY address, not just to loopback. A service bound only to
	// 127.0.0.1 is "listening" but unreachable from every other mesh device, and
	// declaring it as a mesh service would authorize traffic to an endpoint that
	// always refuses. Meaningless unless MeshProbed.
	MeshReachable bool `json:"mesh_reachable"`
	// BindAddrs are the addresses this port is actually bound to (0.0.0.0,
	// 127.0.0.1, a specific IP, ...), read from the kernel's socket table. Only
	// the enumeration path can know this — the dial path leaves it empty. It is
	// the one fact that explains a "loopback only" verdict at a glance.
	BindAddrs []string `json:"bind_addrs,omitempty"`
	// Source is "enumerated" (real socket table, carries BindAddrs and every
	// port) or "dialed" (the curated-list fallback when the platform can't be
	// enumerated). Lets the UI say which view it is showing.
	Source string `json:"source,omitempty"`
}

// Ports returns the dial-probe result for the default port set plus
// any user-extension via $CALABI_PROBE_PORTS (comma-separated). Probes
// run in parallel with a small worker pool so the whole sweep finishes
// in ~250ms even when most ports time out.
//
// ctx bounds the total wall time; per-port deadline is 150ms (any longer
// and we're probably stuck behind a firewall — report "not listening"
// and move on).
// Ports dial-probes the default port set (plus $CALABI_PROBE_PORTS) on
// loopback, and — when overlay is a non-empty mesh address for THIS machine —
// probes each listening port there too, so the caller can tell a service that
// the mesh can actually reach from one bound to loopback only.
func Ports(ctx context.Context, overlay string) []PortInfo {
	wanted := dedup(append(defaultPorts, parseExtraPorts(os.Getenv("CALABI_PROBE_PORTS"))...))
	results := make([]PortInfo, len(wanted))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64) // 64-wide fanout — keeps fd budget sane

	for i, p := range wanted {
		i, p := i, p
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = dialProbe(ctx, p)
		}()
	}
	wg.Wait()

	// Filter to only listening ports — the UI cares about "what's up",
	// not "what's down". Keep the order ascending by port for a stable
	// display.
	out := make([]PortInfo, 0, len(results))
	for _, r := range results {
		if r.Listening {
			if overlay != "" {
				r.MeshProbed = true
				r.MeshReachable = dialOK(ctx, net.JoinHostPort(overlay, strconv.Itoa(r.Port)))
			}
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

// dialProbe is one TCP dial against 127.0.0.1:port. We also try ::1
// — some dev servers bind IPv6-only and would look "down" to an
// IPv4-only probe.
func dialProbe(ctx context.Context, port int) PortInfo {
	pi := PortInfo{Port: port, Hint: hintFor(port)}
	start := time.Now()
	for _, host := range []string{"127.0.0.1", "[::1]"} {
		if dialOK(ctx, host+":"+strconv.Itoa(port)) {
			pi.Listening = true
			pi.latency = time.Since(start)
			pi.LatencyMs = pi.latency.Milliseconds()
			return pi
		}
	}
	return pi
}

// dialOK reports whether something accepts a TCP connection at addr.
//
// Probing the machine's own overlay address is what separates "bound to
// 0.0.0.0" from "bound to 127.0.0.1": the overlay address is assigned locally,
// so the connection stays on this host, but a loopback-only listener still
// refuses it — exactly as a remote mesh peer would be refused.
func dialOK(ctx context.Context, addr string) bool {
	d := net.Dialer{Timeout: 150 * time.Millisecond}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// hintFor returns a one-word hint for well-known ports. Helps the user
// pick the right one out of a list of ten — "5173 (vite)" is friendlier
// than just "5173".
func hintFor(p int) string {
	switch p {
	case 22:
		return "ssh"
	case 80, 443:
		return "http"
	case 3000:
		return "dev (next/express)"
	case 3306:
		return "mysql"
	case 4200:
		return "angular"
	case 5000:
		return "flask"
	case 5173:
		return "vite"
	case 5432:
		return "postgres"
	case 5601:
		return "kibana"
	case 6379:
		return "redis"
	case 7400:
		return "calabi daemon"
	case 8000, 8080:
		return "dev (django/spring)"
	case 8888:
		return "jupyter"
	case 9200:
		return "elasticsearch"
	case 27017:
		return "mongodb"
	case 50051:
		return "grpc"
	}
	return ""
}

func parseExtraPorts(s string) []int {
	if s == "" {
		return nil
	}
	out := []int{}
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		n, err := strconv.Atoi(tok)
		if err == nil && n > 0 && n < 65536 {
			out = append(out, n)
		}
	}
	return out
}

func dedup(in []int) []int {
	seen := make(map[int]struct{}, len(in))
	out := make([]int, 0, len(in))
	for _, p := range in {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}
