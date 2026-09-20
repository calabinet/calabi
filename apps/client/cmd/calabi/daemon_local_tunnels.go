package main

import (
	"net"
	"strconv"
	"strings"

	"github.com/calabinet/calabi/apps/client/internal/mesh"
	"github.com/calabinet/calabi/apps/client/internal/status"
)

// tunnelStates is what the local daemon tells a self-hosted coordinator about
// the tunnels it serves: every configured tunnel, with the address its edge assigned and its live
// counters. A tunnel with no live registration is reported offline.
func (sv *localSupervisor) tunnelStates(state *status.State) []mesh.TunnelState {
	sv.mu.Lock()
	plan := append([]plannedTunnel(nil), sv.planned...)
	live := make(map[int64]liveAddr, len(sv.live))
	for k, v := range sv.live {
		live[k] = v
	}
	sv.mu.Unlock()

	snap := state.SnapshotNow()
	rows := make(map[int64]status.TunnelInfo, len(snap.Tunnels))
	for _, t := range snap.Tunnels {
		if t.TunnelID != 0 {
			rows[t.TunnelID] = t
		}
	}
	edgeHost := sv.edgeAddr()
	if h, _, err := net.SplitHostPort(edgeHost); err == nil {
		edgeHost = h
	}
	out := make([]mesh.TunnelState, 0, len(plan))
	for _, p := range plan {
		domain, port := p.tun.Domain, p.tun.RemotePort
		if la, ok := live[p.id]; ok {
			if la.domain != "" {
				domain = la.domain
			}
			if la.remotePort != 0 {
				port = la.remotePort
			}
		}
		st := mesh.TunnelState{
			Name: p.tun.Name, Type: p.kind, LocalAddr: p.tun.LocalAddr, Status: "offline",
			PublicAddr: tunnelPublicAddr(p.kind, edgeHost, domain, port),
		}
		// The counters travel with their row whatever the connection state, so a
		// report taken during a blip does not reset what the meter counts from.
		if row, ok := rows[p.id]; ok {
			st.Instance, st.BytesIn, st.BytesOut = row.ProxyID, row.BytesIn, row.BytesOut
			switch {
			case !snap.Connected:
			case row.Pending:
				st.Status = "pending"
			default:
				st.Status = "online"
			}
		}
		out = append(out, st)
	}
	return out
}

// tunnelPublicAddr is where visitors reach a tunnel: its host name, or the
// edge's host and the tunnel's port. Empty until there is one.
func tunnelPublicAddr(kind, edgeHost, domain string, port uint32) string {
	switch strings.ToLower(kind) {
	case "http", "https", "sni":
		return domain
	case "tcp", "udp":
		if port != 0 && edgeHost != "" {
			return net.JoinHostPort(edgeHost, strconv.Itoa(int(port)))
		}
	}
	return ""
}
