package core

import (
	"context"
	"fmt"
	"net/netip"
	"time"
)

// NetMapSnapshot owns immutable, meshnet-scoped inputs for one notification
// generation. It never caches a device's authorization result or relay grant.
type NetMapSnapshot struct {
	c            *Coordinator
	meshnet      MeshnetID
	byID         map[int64]*Node
	eligible     []*Node
	doc          *ACLPolicy
	derp         DERPMap
	budget, used int
	rate, burst  uint32
}

// PrepareNetMapSnapshot performs the shared reads once. Its caller must discard
// it when topology or policy changes, including a change during these reads.
func (c *Coordinator) PrepareNetMapSnapshot(ctx context.Context, t MeshnetID) (*NetMapSnapshot, error) {
	all, err := c.nodesWithServices(ctx, t)
	if err != nil {
		return nil, err
	}
	for i, n := range all {
		cp := cloneMapNode(*n)
		all[i] = &cp
	}
	all = safeRealRoutes(all)
	s := &NetMapSnapshot{c: c, meshnet: t, byID: make(map[int64]*Node, len(all)), budget: c.aliasBudgetOf(ctx, t)}
	for _, n := range all {
		if n.Meshnet != t {
			return nil, fmt.Errorf("core: snapshot contains foreign meshnet")
		}
		s.byID[n.ID] = n
		s.used += AliasSpend(n.RouteAliases)
		if n.Approved && !n.Disabled {
			s.eligible = append(s.eligible, n)
		}
	}
	// Freeze one document for both visibility and the inbound packet filter.
	store := c.ACL
	if f, ok := c.Policy.(ACLFilter); ok && store == nil {
		store = f.Store
	}
	if store != nil {
		doc, ok, err := store.GetACL(ctx, t)
		if err != nil {
			return nil, fmt.Errorf("core: read acl: %w", err)
		}
		if ok {
			s.doc = &doc
		}
	}
	if s.doc == nil {
		s.doc, err = policyDocument(c.Policy)
		if err != nil {
			return nil, err
		}
	}
	if s.doc != nil {
		doc := *s.doc
		doc.Groups = make(map[string][]string, len(s.doc.Groups))
		for k, v := range s.doc.Groups {
			doc.Groups[k] = append([]string(nil), v...)
		}
		doc.ACLs = append([]ACLRule(nil), s.doc.ACLs...)
		for i := range doc.ACLs {
			doc.ACLs[i].Src = append([]string(nil), doc.ACLs[i].Src...)
			doc.ACLs[i].Dst = append([]string(nil), doc.ACLs[i].Dst...)
			doc.ACLs[i].Ports = append([]string(nil), doc.ACLs[i].Ports...)
		}
		s.doc = &doc
	}
	s.derp, err = c.DERP.DERPMap(ctx, t)
	if err != nil {
		return nil, fmt.Errorf("core: derp map: %w", err)
	}
	s.derp = cloneMapDERP(s.derp)
	if c.RelayRates != nil {
		s.rate, s.burst = c.RelayRates.RelayRateKbps(ctx, t)
	}
	c.Performance.SnapshotLoads.Add(1)
	return s, nil
}

// NetMapFor derives one device's independent map, checking approval and disable
// state from this version's row rather than issuing another SQL Get.
func (s *NetMapSnapshot) NetMapFor(ctx context.Context, id int64) (result *NetMap, err error) {
	return s.netMapFor(ctx, id, nil)
}

// NetMapViewFor borrows immutable snapshot data during wire encoding. Neither
// the result nor the separately returned peers may be modified. Approval, visibility,
// packet filters and grants are still derived independently for this device.
// The result's Peers field is empty; encode the separately returned peers instead.
func (s *NetMapSnapshot) NetMapViewFor(ctx context.Context, id int64) (*NetMap, []*Node, error) {
	var peers []*Node
	m, err := s.netMapFor(ctx, id, &peers)
	return m, peers, err
}

func (s *NetMapSnapshot) netMapFor(ctx context.Context, id int64, borrowed *[]*Node) (result *NetMap, err error) {
	started := time.Now()
	s.c.Performance.Builds.Add(1)
	defer func() {
		s.c.Performance.BuildNanos.Add(uint64(time.Since(started)))
		if err != nil {
			s.c.Performance.BuildFailures.Add(1)
		} else if result != nil {
			count := len(result.Peers)
			if borrowed != nil {
				count = len(*borrowed)
			}
			s.c.Performance.BuiltPeers.Add(uint64(count))
		}
	}()
	self := s.byID[id]
	if self == nil {
		return nil, ErrNodeNotFound
	}
	return s.forSelfView(ctx, self, borrowed)
}

func (s *NetMapSnapshot) forSelf(ctx context.Context, self *Node) (*NetMap, error) {
	return s.forSelfView(ctx, self, nil)
}

func (s *NetMapSnapshot) forSelfView(ctx context.Context, self *Node, borrowed *[]*Node) (*NetMap, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if self.Meshnet != s.meshnet {
		return nil, ErrNodeNotFound
	}
	if n := s.byID[self.ID]; n != nil {
		self = n
	}
	if self.Disabled {
		return nil, ErrNodeDisabled
	}
	nm := &NetMap{Self: *self, DERP: s.derp, RelayGrant: s.c.relayGrantFor(ctx, self)}
	if borrowed == nil {
		nm.Self = cloneMapNode(*self)
		nm.DERP = cloneMapDERP(s.derp)
	}
	if !self.Approved {
		return nm, nil
	}
	peers := make([]*Node, 0, len(s.eligible))
	for _, n := range s.eligible {
		if n.ID != self.ID {
			peers = append(peers, n)
		}
	}
	if s.doc != nil {
		var err error
		peers, err = (MemPolicy{Policy: *s.doc}).Filter(ctx, s.meshnet, self, peers)
		if err != nil {
			return nil, err
		}
	}
	nm.PacketFilter = s.c.packetFilterFor(self, peers, s.doc)
	nm.UnaliasedRoutes = unaliasedRoutes(self)
	nm.AliasBudgetAddrs, nm.AliasUsedAddrs = s.budget, s.used
	nm.RelayBandwidthKbps, nm.RelayBandwidthBurstKbps = s.rate, s.burst
	if borrowed != nil {
		// The RPC encoder only needs references to these already-filtered frozen
		// nodes. Copying every large Node value per receiver dominated allocation.
		*borrowed = peers
		return nm, nil
	}
	if len(peers) > 0 {
		nm.Peers = make([]Node, 0, len(peers))
	}
	for _, p := range peers {
		nm.Peers = append(nm.Peers, cloneMapNode(*p))
	}
	return nm, nil
}

func cloneMapNode(n Node) Node {
	n.Endpoints = append([]netip.AddrPort(nil), n.Endpoints...)
	n.AdvertisedRoutes = append([]netip.Prefix(nil), n.AdvertisedRoutes...)
	n.ApprovedRoutes = append([]netip.Prefix(nil), n.ApprovedRoutes...)
	n.RealRoutes = append([]netip.Prefix(nil), n.RealRoutes...)
	n.AliasedRoutes = append([]netip.Prefix(nil), n.AliasedRoutes...)
	n.RouteAliases = append([]RouteAlias(nil), n.RouteAliases...)
	n.Services = append([]Service(nil), n.Services...)
	n.Tags = append([]string(nil), n.Tags...)
	if n.BlockIncoming != nil {
		v := *n.BlockIncoming
		n.BlockIncoming = &v
	}
	return n
}

func cloneMapDERP(m DERPMap) DERPMap {
	m.Regions = append([]DERPRegion(nil), m.Regions...)
	for i := range m.Regions {
		m.Regions[i].Nodes = append([]DERPNode(nil), m.Regions[i].Nodes...)
		for j := range m.Regions[i].Nodes {
			m.Regions[i].Nodes[j].TLS.Pins = append([]string(nil), m.Regions[i].Nodes[j].TLS.Pins...)
		}
	}
	return m
}
