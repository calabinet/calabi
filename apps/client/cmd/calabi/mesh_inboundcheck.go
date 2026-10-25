package main

import (
	"net/netip"

	"github.com/calabinet/calabi/apps/client/internal/mesh"
)

func (r *meshRunner) IncomingTCPAllowed(ip netip.Addr, port uint16) bool {
	return r.datapath().IncomingTCPAllowed(ip, port)
}

func (r *meshRunner) DeviceKeyForIP(ip netip.Addr) string {
	r.mu.Lock()
	ctrl := r.ctrl
	r.mu.Unlock()
	return ctrl.DeviceKeyForIP(ip)
}

func (m *localMesh) DeviceKeyForIP(ip netip.Addr) string {
	r := m.runner()
	if r == nil {
		return ""
	}
	return r.DeviceKeyForIP(ip)
}

func (l *runnerLease) DeviceKeyForIP(ip netip.Addr) string { return l.r.DeviceKeyForIP(ip) }

func (c *platformMeshController) DeviceKeyForIP(ip netip.Addr) string {
	c.mu.Lock()
	lease := c.lease
	c.mu.Unlock()
	peers, ok := lease.(mesh.DevicePeerSource)
	if !ok {
		return ""
	}
	return peers.DeviceKeyForIP(ip)
}

func (m *localMesh) IncomingTCPAllowed(ip netip.Addr, port uint16) bool {
	r := m.runner()
	return r != nil && r.IncomingTCPAllowed(ip, port)
}

func (l *runnerLease) IncomingTCPAllowed(ip netip.Addr, port uint16) bool {
	return l.r.IncomingTCPAllowed(ip, port)
}

func (c *platformMeshController) IncomingTCPAllowed(ip netip.Addr, port uint16) bool {
	c.mu.Lock()
	lease := c.lease
	c.mu.Unlock()
	p, ok := lease.(mesh.InboundPolicySource)
	return ok && p.IncomingTCPAllowed(ip, port)
}
