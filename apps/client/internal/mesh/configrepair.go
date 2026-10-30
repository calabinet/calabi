package mesh

import (
	"net/netip"
	"time"
)

// A repair job exists only while a configuration operation is incomplete. It
// owns no historical graph, uses bounded backoff, and is joined before Close
// tears down WireGuard or OS routes. A new map atomically replaces the target.
func (d *WGDatapath) repairConfigLoop() {
	defer d.repairWG.Done()
	delay := time.Second
	for {
		timer := time.NewTimer(delay)
		select {
		case <-d.repairStop:
			timer.Stop()
			d.peerConfigMu.Lock()
			d.repairRunning = false
			d.peerConfigMu.Unlock()
			return
		case <-timer.C:
		}
		d.peerConfigMu.Lock()
		if d.configClosed || d.repairDesired == nil {
			d.repairRunning = false
			d.peerConfigMu.Unlock()
			return
		}
		cfg := *d.repairDesired
		version := d.configGeneration.Load()
		err := d.applyPeerConfigLocked(cfg)
		d.peerConfigMu.Unlock()
		needed := false
		if err == nil {
			d.routeConfigMu.Lock()
			if d.configGeneration.Load() == version {
				needed, err = d.applyRouteConfig(cfg)
			} else {
				needed = true
			}
			d.routeConfigMu.Unlock()
		}
		d.peerConfigMu.Lock()
		if d.configClosed || d.repairDesired == nil {
			d.repairRunning = false
			d.peerConfigMu.Unlock()
			return
		}
		if d.configGeneration.Load() != version {
			d.peerConfigMu.Unlock()
			delay = time.Second
			continue
		}
		// Reconcile only this generation: a slow route call cannot restore an
		// older relay selection after the next map already changed its trust.
		d.relays.Reconcile(cfg.SelfRelay, peerRelayAddrs(cfg))
		if err == nil && !needed {
			d.repairDesired = nil
			d.repairRunning = false
			d.peerConfigMu.Unlock()
			return
		}
		d.peerConfigMu.Unlock()
		delay = min(30*time.Second, delay*2)
	}
}

// Only failed applies need another retained representation. The normal path
// retains no WGConfig for repair. Copy mutable fields so caller changes cannot
// change permissions while a retry is waiting.
func cloneRepairConfig(c WGConfig) WGConfig {
	c.Peers = append([]WGPeer(nil), c.Peers...)
	for i := range c.Peers {
		c.Peers[i].AllowedIPs = append([]netip.Prefix(nil), c.Peers[i].AllowedIPs...)
	}
	c.Filter = append([]FilterRule(nil), c.Filter...)
	for i := range c.Filter {
		c.Filter[i].SrcCIDRs = append([]netip.Prefix(nil), c.Filter[i].SrcCIDRs...)
		c.Filter[i].DstPorts = append([]PortRange(nil), c.Filter[i].DstPorts...)
	}
	c.SubnetAliases = append([]SubnetAlias(nil), c.SubnetAliases...)
	c.UnaliasedRoutes = append([]SubnetAlias(nil), c.UnaliasedRoutes...)
	c.PublishedRoutes = append([]netip.Prefix(nil), c.PublishedRoutes...)
	c.RelayGrant = append([]byte(nil), c.RelayGrant...)
	regions := make(map[string]string, len(c.RelayByRegion))
	for k, v := range c.RelayByRegion {
		regions[k] = v
	}
	c.RelayByRegion = regions
	tls := make(map[string]RelayTLS, len(c.RelayTLS))
	for k, v := range c.RelayTLS {
		v.Pins = append([]string(nil), v.Pins...)
		tls[k] = v
	}
	c.RelayTLS = tls
	return c
}
