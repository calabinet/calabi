package mesh

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strconv"
)

// IncomingTCPAllowed rechecks the current rule set without the established-flow
// exemption. Application-level sessions must honor revocation on keep-alive TCP
// connections too. Membership/identity is checked separately by the caller.
func (d *WGDatapath) IncomingTCPAllowed(source netip.Addr, port uint16) bool {
	if d == nil || d.filter == nil || !source.IsValid() || port == 0 {
		return false
	}
	return d.filter.allow(tuple{src: source, proto: 6, dstPort: port})
}

// InboundPolicySource is optional on local daemon mesh providers. An older or
// unavailable provider denies the check; it never silently assumes allow-all.
type InboundPolicySource interface{ IncomingTCPAllowed(netip.Addr, uint16) bool }

type DevicePeerSource interface{ DeviceKeyForIP(netip.Addr) string }

// InboundPolicyHandler exposes only a rule decision on the existing local API.
// It does not open sockets, transfer files, or expose any file metadata.
func InboundPolicyHandler(source any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ip, err := netip.ParseAddr(r.URL.Query().Get("source"))
		port, portErr := strconv.ParseUint(r.URL.Query().Get("port"), 10, 16)
		if err != nil || portErr != nil || port == 0 {
			http.Error(w, "exact source IP and TCP port required", 400)
			return
		}
		p, ok := source.(InboundPolicySource)
		if !ok {
			http.Error(w, "live inbound policy unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		key := ""
		if peers, ok := source.(DevicePeerSource); ok {
			key = peers.DeviceKeyForIP(ip)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"allowed": p.IncomingTCPAllowed(ip, uint16(port)), "peer_key": key})
	}
}
