package mesh

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/hostnet"
	"github.com/calabinet/calabi/pkg/mesh-proto/stun"
)

// NATType classifies the host's observed NAT behavior.
type NATType string

const (
	NATOpen               NATType = "open"
	NATFullCone           NATType = "full_cone"
	NATRestrictedCone     NATType = "restricted_cone"
	NATPortRestrictedCone NATType = "port_restricted_cone"
	NATCone               NATType = "cone"
	NATSymmetric          NATType = "symmetric"
	NATUDPBlocked         NATType = "udp_blocked"
	NATUnknown            NATType = "unknown"
)

// HolePunchVerdict summarizes whether peer-to-peer UDP hole punching is expected
// to work from this network.
type HolePunchVerdict string

const (
	HolePunchDirect    HolePunchVerdict = "direct"
	HolePunchSupported HolePunchVerdict = "supported"
	HolePunchLimited   HolePunchVerdict = "limited"
	HolePunchBlocked   HolePunchVerdict = "blocked"
	HolePunchUnknown   HolePunchVerdict = "unknown"
)

// NATReport is the JSON payload served by GET /v1/netcheck across desktop
// (platform & standalone) and mobile clients. It is strictly on-demand and must
// never be forwarded to control-plane telemetry.
type NATReport struct {
	NATType     NATType          `json:"nat_type"`
	HolePunch   HolePunchVerdict `json:"hole_punch"`
	OverlayIP   string           `json:"overlay_ip,omitempty"`
	LocalIP     string           `json:"local_ip,omitempty"`
	LocalIPs    []string         `json:"local_ips,omitempty"`
	PublicIP    string           `json:"public_ip,omitempty"`
	PublicPort  uint16           `json:"public_port,omitempty"`
	IPv6        string           `json:"ipv6,omitempty"`
	PortVaries  *bool            `json:"port_varies,omitempty"`
	ProbeSource string           `json:"probe_source,omitempty"`
	ProbedAt    time.Time        `json:"probed_at"`
	DurationMS  int64            `json:"duration_ms"`
	ServersUsed int              `json:"servers_used"`
	Detail      string           `json:"detail,omitempty"`
}

// NATCheckOptions configures one on-demand CheckNAT run.
type NATCheckOptions struct {
	// OverlayIP is the node's own mesh overlay IP (100.64.x.x), echoed into the
	// report for display convenience.
	OverlayIP string
	// STUNServers are own Edge STUN host:port endpoints from the live DERP map.
	// Stage 1 uses up to 2 distinct IPv4 servers from this list.
	STUNServers []string
	// RFC5780Servers are optional dual-IP RFC 5780 STUN servers (used in Stage 2
	// to distinguish NAT1/NAT2/NAT3). When empty and AllowPublicSTUN is true,
	// DefaultPublicRFC5780Servers is used.
	RFC5780Servers []string
	// AllowPublicSTUN permits Stage 2 fallback to DefaultPublicRFC5780Servers.
	// Must be false in self-hosted / standalone mode so the client never contacts
	// third-party public STUN servers.
	AllowPublicSTUN bool
	// AttemptTimeout overrides the per-UDP-attempt timeout (default 750ms).
	AttemptTimeout time.Duration
	// allowSameIPOther relaxes the distinct-IP requirement on OTHER-ADDRESS for
	// loopback unit tests on platforms without 127.0.0.2.
	allowSameIPOther bool
}

// DefaultPublicRFC5780Servers are public dual-IP STUN servers used ONLY in
// platform mode when no platform-owned RFC 5780 STUN server is advertised via
// enrollment (or configured via CALABI_RFC5780_STUN).
var DefaultPublicRFC5780Servers = []string{
	"stun.miwifi.com:3478",
	"stun.stunprotocol.org:3478",
	"stun.sipgate.net:3478",
}

const (
	defaultNATAttemptTimeout = 750 * time.Millisecond
	natCheckTotalTimeout     = 7 * time.Second
)

// CheckNAT performs a two-stage on-demand NAT and IP diagnostic:
//
//   - Stage 1 (Mapping): sends RFC 5389 Binding Requests from a single UDP4
//     socket to up to 2 distinct IPv4 Edge STUN servers to classify open,
//     symmetric (NAT4), cone (NAT1-3), or udp_blocked.
//   - Stage 2 (Filtering): when Stage 1 reports cone (or had <2 servers and
//     RFC 5780 servers are allowed), runs RFC 5780 CHANGE-REQUEST tests to
//     refine cone into full_cone (NAT1), restricted_cone (NAT2), or
//     port_restricted_cone (NAT3). If Stage 2 is unavailable or disabled, it
//     degrades cleanly to Stage 1's honest result.
func CheckNAT(ctx context.Context, opts NATCheckOptions) (report NATReport) {
	start := time.Now()
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, natCheckTotalTimeout)
		defer cancel()
	}
	attemptTimeout := opts.AttemptTimeout
	if attemptTimeout <= 0 {
		attemptTimeout = defaultNATAttemptTimeout
	}

	report = NATReport{
		NATType:     NATUnknown,
		HolePunch:   HolePunchUnknown,
		OverlayIP:   strings.TrimSpace(opts.OverlayIP),
		ProbeSource: "none",
		ProbedAt:    time.Now().UTC(),
	}
	defer func() {
		report.ProbedAt = time.Now().UTC()
		report.DurationMS = time.Since(start).Milliseconds()
		report.HolePunch = verdictForNAT(report.NATType)
	}()

	edgeEndpoints := resolveUniqueIPv4Endpoints(ctx, opts.STUNServers, 3)

	var hintIP netip.Addr
	if len(edgeEndpoints) > 0 {
		hintIP = edgeEndpoints[0].Addr()
	}
	localV4, allLocalV4, globalV6 := discoverLocalAddrs(ctx, hintIP)
	if localV4.IsValid() {
		report.LocalIP = localV4.String()
	}
	if len(allLocalV4) > 0 {
		report.LocalIPs = make([]string, 0, len(allLocalV4))
		for _, ip := range allLocalV4 {
			report.LocalIPs = append(report.LocalIPs, ip.String())
		}
	}
	if globalV6.IsValid() {
		report.IPv6 = globalV6.String()
	}

	// Stage 1: Mapping probe against own Edge STUN servers.
	var stage1Mapped []stun.BindingDetail
	var stage1Servers []netip.AddrPort
	var stage1LocalPort uint16

	if len(edgeEndpoints) > 0 {
		pc, err := hostnet.ListenConfig().ListenPacket(ctx, "udp4", ":0")
		if err == nil {
			if ua, ok := pc.LocalAddr().(*net.UDPAddr); ok {
				stage1LocalPort = uint16(ua.Port)
			}
			for _, ep := range edgeEndpoints {
				if len(stage1Mapped) >= 2 {
					break
				}
				d, ok := stunProbeOnce(ctx, pc, ep, stun.BindingRequest, attemptTimeout, 2)
				if ok {
					stage1Mapped = append(stage1Mapped, d)
					stage1Servers = append(stage1Servers, ep)
				}
			}
			_ = pc.Close()
		}
	}

	report.ServersUsed = len(stage1Mapped)
	stage1ConfirmedCone := false

	switch len(stage1Mapped) {
	case 0:
		if len(edgeEndpoints) > 0 {
			// Edge STUN servers resolved, yet none answered.
			report.NATType = NATUDPBlocked
			report.ProbeSource = "edge"
			report.Detail = "edge_stun_timeout"
			return report
		}
	case 1:
		m1 := stage1Mapped[0].Mapped
		report.PublicIP = m1.Addr().String()
		report.PublicPort = m1.Port()
		report.ProbeSource = "edge"
		if isDirectPublicMatch(localV4, stage1LocalPort, m1) {
			report.NATType = NATOpen
			v := false
			report.PortVaries = &v
			return report
		}
		// If this single Edge STUN server itself advertises RFC 5780 OTHER-ADDRESS,
		// run Stage 2 directly against it without touching any third-party server.
		if hasDistinctOther(stage1Servers[0], stage1Mapped[0].Other, opts.allowSameIPOther) {
			if refined, ok := runRFC5780Server(ctx, stage1Servers[0], localV4, attemptTimeout, opts.allowSameIPOther, nil); ok {
				mergeRFC5780(&report, refined, "calabi_rfc5780")
				return report
			}
		}
		report.Detail = "single_stun_server"
	default:
		m1 := stage1Mapped[0].Mapped
		m2 := stage1Mapped[1].Mapped
		report.PublicIP = m1.Addr().String()
		report.PublicPort = m1.Port()
		report.ProbeSource = "edge"
		varies := m1.Addr() != m2.Addr() || m1.Port() != m2.Port()
		report.PortVaries = &varies
		if !varies && isDirectPublicMatch(localV4, stage1LocalPort, m1) {
			report.NATType = NATOpen
			return report
		}
		if varies {
			report.NATType = NATSymmetric
			return report
		}
		report.NATType = NATCone
		stage1ConfirmedCone = true
	}

	// Stage 2: RFC 5780 filtering probe (and mapping fallback when Stage 1 had <2 servers).
	// Priority:
	//   1. CALABI_RFC5780_STUN env var ("off" disables Stage 2; otherwise comma-separated host:port)
	//   2. opts.RFC5780Servers (e.g. platform-advertised nat_stun_addr from enrollment)
	//   3. Platform mode only (AllowPublicSTUN=true): DefaultPublicRFC5780Servers fallback.
	// When the platform has not configured nat_stun_addr, clients never touch any
	// unconfigured platform STUN domain and go directly to the public fallback.
	type rfc5780Candidate struct {
		addr   string
		source string
	}
	var candidates []rfc5780Candidate
	envOverride := strings.TrimSpace(os.Getenv("CALABI_RFC5780_STUN"))
	if !strings.EqualFold(envOverride, "off") {
		if envOverride != "" {
			for _, raw := range strings.Split(envOverride, ",") {
				if s := strings.TrimSpace(raw); s != "" {
					candidates = append(candidates, rfc5780Candidate{addr: s, source: "calabi_rfc5780"})
				}
			}
		} else {
			for _, raw := range opts.RFC5780Servers {
				if s := strings.TrimSpace(raw); s != "" {
					candidates = append(candidates, rfc5780Candidate{addr: s, source: "calabi_rfc5780"})
				}
			}
		}
		if opts.AllowPublicSTUN {
			for _, s := range DefaultPublicRFC5780Servers {
				candidates = append(candidates, rfc5780Candidate{addr: s, source: "public_rfc5780"})
			}
		}
	}
	if len(candidates) == 0 {
		if report.NATType == NATUnknown && len(edgeEndpoints) == 0 {
			report.Detail = "no_stun_servers"
		}
		return report
	}

	var knownVaries *bool
	if stage1ConfirmedCone {
		v := false
		knownVaries = &v
	}
	resolvedAny := false
	seenStage2IP := make(map[netip.Addr]bool)
	for _, cand := range candidates {
		if ctx.Err() != nil {
			break
		}
		eps := resolveUniqueIPv4Endpoints(ctx, []string{cand.addr}, 1)
		if len(eps) == 0 || seenStage2IP[eps[0].Addr()] {
			continue
		}
		seenStage2IP[eps[0].Addr()] = true
		resolvedAny = true
		refined, ok := runRFC5780Server(ctx, eps[0], localV4, attemptTimeout, opts.allowSameIPOther, knownVaries)
		if ok {
			mergeRFC5780(&report, refined, cand.source)
			return report
		}
	}

	// Stage 2 did not yield an RFC 5780 answer. If Stage 1 already succeeded
	// (cone or single server), preserve Stage 1 cleanly; otherwise report DNS/UDP failure.
	if report.NATType == NATUnknown && len(stage1Mapped) == 0 {
		if !resolvedAny {
			report.Detail = "stun_dns_failed"
		} else {
			report.NATType = NATUDPBlocked
			report.ProbeSource = "rfc5780"
			report.Detail = "stun_timeout"
		}
	}
	return report
}

type rfc5780Result struct {
	natType    NATType
	mapped     netip.AddrPort
	portVaries *bool
	usedOther  bool
}

func mergeRFC5780(report *NATReport, r rfc5780Result, source string) {
	report.NATType = r.natType
	if r.mapped.IsValid() {
		report.PublicIP = r.mapped.Addr().String()
		report.PublicPort = r.mapped.Port()
	}
	if r.portVaries != nil {
		report.PortVaries = r.portVaries
	}
	if source == "" {
		source = "rfc5780"
	}
	report.ProbeSource = source
	report.Detail = ""
	if r.usedOther && report.ServersUsed < 2 {
		report.ServersUsed = 2
	} else if report.ServersUsed < 1 {
		report.ServersUsed = 1
	}
}

func runRFC5780Server(
	ctx context.Context,
	primary netip.AddrPort,
	localV4 netip.Addr,
	attemptTimeout time.Duration,
	allowSameIPOther bool,
	knownVaries *bool,
) (rfc5780Result, bool) {
	pc, err := hostnet.ListenConfig().ListenPacket(ctx, "udp4", ":0")
	if err != nil {
		return rfc5780Result{}, false
	}
	defer pc.Close()

	var localPort uint16
	if ua, ok := pc.LocalAddr().(*net.UDPAddr); ok {
		localPort = uint16(ua.Port)
	}

	// Test I: plain Binding Request to primary IP:Port.
	d1, ok := stunProbeOnce(ctx, pc, primary, stun.BindingRequest, attemptTimeout, 2)
	if !ok {
		return rfc5780Result{}, false
	}
	if isDirectPublicMatch(localV4, localPort, d1.Mapped) {
		v := false
		return rfc5780Result{natType: NATOpen, mapped: d1.Mapped, portVaries: &v}, true
	}

	other := d1.Other
	if !hasDistinctOther(primary, other, allowSameIPOther) {
		return rfc5780Result{}, false
	}

	// If Stage 1 hasn't already verified mapping independence, probe OTHER-ADDRESS
	// from the exact same local UDP socket.
	portVaries := knownVaries
	if portVaries == nil {
		d2, ok := stunProbeOnce(ctx, pc, other, stun.BindingRequest, attemptTimeout, 2)
		if !ok {
			return rfc5780Result{}, false
		}
		v := d1.Mapped.Addr() != d2.Mapped.Addr() || d1.Mapped.Port() != d2.Mapped.Port()
		portVaries = &v
		if v {
			return rfc5780Result{natType: NATSymmetric, mapped: d1.Mapped, portVaries: portVaries, usedOther: true}, true
		}
	}

	// Test II: CHANGE-REQUEST (ChangeIP + ChangePort). A reply arrives from
	// OTHER-ADDRESS, proving Endpoint-Independent Filtering (NAT1 Full Cone).
	if _, ok := stunProbeOnce(ctx, pc, primary, func(tx stun.TxID) []byte {
		return stun.BindingRequestChange(tx, true, true)
	}, attemptTimeout, 2); ok {
		return rfc5780Result{natType: NATFullCone, mapped: d1.Mapped, portVaries: portVaries, usedOther: true}, true
	}

	// Test III: CHANGE-REQUEST (ChangePort only). A reply arrives from the same
	// IP on its alternate port, proving Address-Restricted Cone (NAT2).
	if _, ok := stunProbeOnce(ctx, pc, primary, func(tx stun.TxID) []byte {
		return stun.BindingRequestChange(tx, false, true)
	}, attemptTimeout, 2); ok {
		return rfc5780Result{natType: NATRestrictedCone, mapped: d1.Mapped, portVaries: portVaries, usedOther: true}, true
	}

	// Neither Test II nor Test III returned, while Test I (and mapping check)
	// succeeded -> Port-Restricted Cone (NAT3).
	return rfc5780Result{natType: NATPortRestrictedCone, mapped: d1.Mapped, portVaries: portVaries, usedOther: true}, true
}

func stunProbeOnce(
	ctx context.Context,
	pc net.PacketConn,
	server netip.AddrPort,
	buildReq func(stun.TxID) []byte,
	attemptTimeout time.Duration,
	attempts int,
) (stun.BindingDetail, bool) {
	dst := net.UDPAddrFromAddrPort(server)
	buf := make([]byte, 1500)
	for range attempts {
		if ctx.Err() != nil {
			return stun.BindingDetail{}, false
		}
		tx, err := stun.NewTxID()
		if err != nil {
			return stun.BindingDetail{}, false
		}
		if _, err := pc.WriteTo(buildReq(tx), dst); err != nil {
			return stun.BindingDetail{}, false
		}
		deadline := time.Now().Add(attemptTimeout)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		for {
			_ = pc.SetReadDeadline(deadline)
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				break
			}
			if detail, ok := stun.ParseBindingResponseDetail(buf[:n], tx); ok {
				return detail, true
			}
			// Ignore stray or late replies from earlier probes until deadline.
		}
	}
	return stun.BindingDetail{}, false
}

func hasDistinctOther(primary, other netip.AddrPort, allowSameIP bool) bool {
	if !other.IsValid() || !other.Addr().Is4() || other.Port() == 0 {
		return false
	}
	if other.Port() == primary.Port() {
		return false
	}
	if !allowSameIP && other.Addr() == primary.Addr() {
		return false
	}
	return true
}

func isDirectPublicMatch(localV4 netip.Addr, localPort uint16, mapped netip.AddrPort) bool {
	if !localV4.IsValid() || !mapped.IsValid() {
		return false
	}
	if localV4.Unmap() != mapped.Addr().Unmap() {
		return false
	}
	return localPort == 0 || localPort == mapped.Port()
}

func verdictForNAT(t NATType) HolePunchVerdict {
	switch t {
	case NATOpen, NATFullCone:
		return HolePunchDirect
	case NATRestrictedCone, NATPortRestrictedCone, NATCone:
		return HolePunchSupported
	case NATSymmetric:
		return HolePunchLimited
	case NATUDPBlocked:
		return HolePunchBlocked
	default:
		return HolePunchUnknown
	}
}

func resolveUniqueIPv4Endpoints(ctx context.Context, servers []string, limit int) []netip.AddrPort {
	seenIP := make(map[netip.Addr]bool)
	var out []netip.AddrPort
	for _, raw := range servers {
		if len(out) >= limit || ctx.Err() != nil {
			break
		}
		host, portStr, err := net.SplitHostPort(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			continue
		}
		var ip netip.Addr
		if parsed, err := netip.ParseAddr(host); err == nil {
			parsed = parsed.Unmap()
			if parsed.Is4() {
				ip = parsed
			}
		} else {
			rctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
			ips, lerr := hostnet.Resolver().LookupNetIP(rctx, "ip4", host)
			cancel()
			if lerr == nil {
				for _, cand := range ips {
					cand = cand.Unmap()
					if cand.Is4() {
						ip = cand
						break
					}
				}
			}
		}
		if !ip.IsValid() || seenIP[ip] {
			continue
		}
		seenIP[ip] = true
		out = append(out, netip.AddrPortFrom(ip, uint16(port)))
	}
	return out
}

func discoverLocalAddrs(ctx context.Context, hintIPv4 netip.Addr) (localV4 netip.Addr, allV4 []netip.Addr, globalV6 netip.Addr) {
	overlay := netip.MustParsePrefix(meshOverlayCIDR)
	isUsableV4 := func(a netip.Addr) bool {
		a = a.Unmap()
		return a.IsValid() && a.Is4() && !a.IsLoopback() && !a.IsUnspecified() && !a.IsLinkLocalUnicast() && !a.IsMulticast() && !overlay.Contains(a)
	}
	isGlobalV6 := func(a netip.Addr) bool {
		a = a.Unmap()
		return a.IsValid() && a.Is6() && a.IsGlobalUnicast() && !a.IsPrivate() && !a.IsLoopback() && !a.IsLinkLocalUnicast()
	}

	// Default-route local IPv4 via non-sending UDP dial (kernel route lookup only).
	targetV4 := "223.5.5.5:53"
	if hintIPv4.IsValid() && hintIPv4.Is4() && !hintIPv4.IsLoopback() {
		targetV4 = netip.AddrPortFrom(hintIPv4, 3478).String()
	}
	if conn, err := hostnet.Dialer().DialContext(ctx, "udp4", targetV4); err == nil {
		if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			if ip, ok := netip.AddrFromSlice(ua.IP); ok && isUsableV4(ip) {
				localV4 = ip.Unmap()
			}
		}
		_ = conn.Close()
	}

	// Default-route global IPv6 via non-sending UDP6 dial.
	if conn, err := hostnet.Dialer().DialContext(ctx, "udp6", "[2606:4700:4700::1111]:53"); err == nil {
		if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			if ip, ok := netip.AddrFromSlice(ua.IP); ok && isGlobalV6(ip) {
				globalV6 = ip.Unmap()
			}
		}
		_ = conn.Close()
	}

	ifaces, err := hostnet.Interfaces()
	if err == nil {
		seen := make(map[netip.Addr]bool)
		var fallbackV4 netip.Addr
		for _, ifc := range ifaces {
			if !ifc.Up || ifc.Loopback {
				continue
			}
			virtual := isVirtualIfaceName(ifc.Name)
			for _, a := range ifc.Addrs {
				ip := a.Addr.Unmap()
				if isUsableV4(ip) {
					if !virtual && !seen[ip] {
						seen[ip] = true
						allV4 = append(allV4, ip)
					}
					if !fallbackV4.IsValid() && !virtual {
						fallbackV4 = ip
					}
				} else if !globalV6.IsValid() && !virtual && isGlobalV6(ip) {
					globalV6 = ip
				}
			}
		}
		if !localV4.IsValid() {
			localV4 = fallbackV4
		}
	}
	if localV4.IsValid() {
		found := false
		for _, ip := range allV4 {
			if ip == localV4 {
				found = true
				break
			}
		}
		if !found {
			allV4 = append([]netip.Addr{localV4}, allV4...)
		}
	}
	return localV4, allV4, globalV6
}

func isVirtualIfaceName(name string) bool {
	low := strings.ToLower(strings.TrimSpace(name))
	for _, pfx := range []string{
		"docker", "br-", "veth", "virbr", "vmnet", "vbox", "vethernet",
		"wsl", "tailscale", "calabi", "wg", "tun", "utun", "tap", "zt",
	} {
		if strings.HasPrefix(low, pfx) || strings.Contains(low, "wsl") || strings.Contains(low, "virtualbox") || strings.Contains(low, "vmware") {
			return true
		}
	}
	return false
}
