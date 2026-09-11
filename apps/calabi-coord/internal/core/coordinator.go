package core

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"sync"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// ErrNodeDisabled is returned by Register when a disabled node tries to
// (re)enroll. The RPC layer maps it to PermissionDenied so the client sees a
// clear refusal and its reconnect loop can't quietly rejoin the mesh.
var ErrNodeDisabled = errors.New("core: node is disabled")

// Coordinator is the deployment-agnostic brain. It is constructed by the wire_*.go
// seam with either self-hosted (in-memory/file) or platform (DB/tenant) stores and
// is the SAME code the self-hosted coordinator ships.
type Coordinator struct {
	Nodes  NodeStore
	Policy PolicyStore
	IPAM   IPAM
	// AliasIPAM hands out stand-in prefixes for subnet routes that would collide
	// with consumers' own LANs. Nil = this deployment does not offer aliasing:
	// requests are simply not granted and routes publish under their real CIDRs,
	// exactly as before the feature existed.
	AliasIPAM AliasIPAM
	DERP      DERPMapSource
	// Quota caps how many nodes a meshnet may enroll (MESH.8). Nil = unlimited
	// (dev/tests). Checked only when admitting a genuinely NEW node.
	Quota NodeQuota
	// ACL is the writable per-meshnet ACL store the console editor reads/writes
	// (MESH.8e-2). Nil on the self-hosted build (its single ACL is a file), where
	// the admin ACL endpoints report NotImplemented. When set, it is normally the
	// SAME store ACLFilter reads for netmap filtering, so a saved edit takes
	// effect on the next netmap push (the admin surface bumps after a write).
	ACL ACLStore
	// Settings holds per-meshnet switches (device approval). Nil = defaults only.
	Settings SettingsStore
	// Relays is the registry of relays each ORG runs itself (R2, relay.go). Nil =
	// no self-hosted relays; every meshnet then sees exactly the platform map.
	Relays RelayStore
	// Services is the registry of what each node OFFERS (declared by a person in
	// the console, never discovered from the node). Nil = no registry.
	Services ServiceStore
	// ACLRevisions keeps the history of saved ACL documents so the console can
	// restore a previous one (MESH.8e-3). Nil = no history (ACL editing still
	// works); the self-hosted build can wire the in-memory store.
	ACLRevisions ACLRevisionStore
	// Presence tracks which nodes hold a live control stream (are online now),
	// distinct from Disabled (admin) and LastSeen (last register). The RPC layer
	// marks/clears it around each PullNetMap stream; the admin surface reads it so
	// the console can show online/offline. Nil is safe (everything reads offline).
	Presence *Presence
	// ServiceHealth is what each node OBSERVES about its own services (F3b).
	// In-memory and current-value-only, like Presence. Nil is safe: the console
	// then shows nothing observed, which is honest rather than wrong.
	ServiceHealth *ServiceHealthTracker
	// DefaultDERPHome is the relay region code stamped on a node that has no home
	// of its own yet (MESH.4): the deployment's home region, from the DERP map
	// config (CALABI_COORD_DERP_HOME_REGION / first region). It makes a node's
	// "relay home" concrete — surfaced in the console/admin node list and used to
	// reach the node via relay. Empty = leave the node's home blank (don't invent
	// a region). Latency-based, client-reported home lands with endpoint discovery.
	//
	// It stays a single string, not a per-meshnet lookup, and that is what keeps a
	// SELF-HOSTED region from ever being a node's default home: the value comes
	// from platform config, and every meshnet's map contains the platform regions.
	// A new node hasn't measured anything yet, so defaulting it to the org's own
	// VPS would bet its first connectivity on a machine nobody has checked.
	// R2 must therefore keep including the platform regions in every org's map.
	DefaultDERPHome string
	// RelayGrants signs the relay authorization carried in each netmap (R0').
	// Nil = this coordinator issues none, which is correct while its relays still
	// run with relay.require_auth off. See relaygrant.go.
	RelayGrants RelayGrantIssuer
	Logger      *slog.Logger

	// enrollLocks serializes enrollment PER MESHNET.
	//
	// Register decides on a snapshot and then writes: it counts the meshnet's
	// active nodes, asks the quota backend whether one more fits, allocates an
	// address and inserts. Run concurrently, every caller read the same count and
	// every caller passed, so one burst bought far more seats than the plan
	// allows (audit finding MESH-12) — quota-svc cannot catch it either, because
	// the count it judges is the one the caller supplied.
	//
	// The same snapshot feeds the name-uniqueness and route-overlap rules, so
	// serializing here closes those races too rather than only the seat one.
	//
	// One process, like the v2 session table: a multi-replica coordinator would
	// need a shared lock (or a unique seat row) instead. The zero value works, so
	// callers that build a Coordinator literal need not initialize it.
	enrollLocks sync.Map // MeshnetID -> *sync.Mutex
}

// lockMeshnet serializes one meshnet's enrollments and returns the unlock func.
func (c *Coordinator) lockMeshnet(t MeshnetID) func() {
	v, _ := c.enrollLocks.LoadOrStore(t, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// RegisterInput carries the fields a node presents at enrollment.
type RegisterInput struct {
	Meshnet  MeshnetID
	Name     string
	NodeKey  meshproto.NodeKey
	DiscoKey meshproto.DiscoKey
	// OwnerUserID is the human behind the auth key (resolved, never self-asserted).
	OwnerUserID int64
	// Tags are the ACL tags resolved from the auth key (authoritative; never
	// self-asserted). Stamped onto the node so tag:/group: ACL rules match.
	Tags []string
	// DeviceFingerprint is the daemon's per-install id (a claim; display only).
	DeviceFingerprint string
	// DeclaredServices are the services the node's OWN CONFIG declares. A
	// claim: they land pending and an admin confirms them before any ACL
	// "svc:" rule matches. Only Name/Proto/Port/Note are read.
	DeclaredServices []Service
	// AdvertisedRoutes are subnet-router CIDRs the node offers to forward (MESH.7).
	// A claim; approval is the admin's (see Node.ApprovedRoutes).
	AdvertisedRoutes []netip.Prefix
	// AliasedRoutes are the advertised CIDRs the node asks to publish under a
	// unique stand-in prefix, because it expects them to collide with consumers'
	// own LANs. A request, like the claim above; see Node.AliasedRoutes.
	AliasedRoutes []netip.Prefix
	// Auth (auth_key verification, meshnet + tag resolution) happens in the RPC
	// layer BEFORE calling Register — the core trusts the resolved Identity.
}

// Register allocates an overlay address and persists the node. It is idempotent
// by node key within a meshnet: a node reconnecting with the same key keeps its
// id + overlay (so a daemon's reconnect loop doesn't churn addresses or leave
// stale peers in the netmap).
func (c *Coordinator) Register(ctx context.Context, in RegisterInput) (*Node, error) {
	if in.NodeKey.IsZero() {
		return nil, fmt.Errorf("core: register: node_key is zero")
	}
	// One gate, ahead of BOTH the re-enrollment and the fresh-node path below: a
	// route too wide to ever be aliased never enters the node's state, so nothing
	// downstream (approval, publication, alias reconciliation, ACL selectors) has
	// to remember to filter it. Applied to AliasedRoutes too — it is a subset of
	// the advertisement, and leaving a request behind for a route that no longer
	// exists would show the console a request that can never be granted.
	// See routelimits.go for why the width limit exists.
	keptRoutes, refusedRoutes := splitAdvertised(in.AdvertisedRoutes)
	in.AdvertisedRoutes = keptRoutes
	in.AliasedRoutes, _ = splitAdvertised(in.AliasedRoutes)
	if len(refusedRoutes) > 0 && c.Logger != nil {
		c.Logger.Warn("refusing subnet routes: not publishable (wider than the maximum, or inside the mesh's own address space)",
			"meshnet", in.Meshnet, "refused", refusedRoutes,
			"max_prefix_bits", advertiseMinBitsV4, "reserved", carrierGradeNAT)
	}
	// Everything from here to the insert is decide-then-write on a snapshot, so
	// it runs one-at-a-time per meshnet (MESH-12). Held across the store calls
	// deliberately: the seat count, the name check and the route-overlap check
	// all read the same snapshot, and a lock that ended before the write would
	// leave every one of them racy.
	defer c.lockMeshnet(in.Meshnet)()

	// The meshnet's nodes, fetched once. Three rules below read them: a name may
	// not collide with a peer's (MESH-5), a CIDR a peer already publishes is not
	// auto-approved (MESH-1), and the seat gate counts them.
	peers, err := c.Nodes.ListMeshnet(ctx, in.Meshnet)
	if err != nil {
		return nil, fmt.Errorf("core: list meshnet: %w", err)
	}

	// Re-enrollment: reuse the existing node (same id + overlay), just refresh the
	// mutable fields. No new IPAM allocation.
	if existing, err := c.Nodes.FindByKey(ctx, in.Meshnet, in.NodeKey); err == nil && existing != nil {
		// An admin-disabled node may not rejoin (MESH.8b) — refuse before touching
		// any state, so its reconnect loop can't quietly re-enroll.
		if existing.Disabled {
			if c.Logger != nil {
				c.Logger.Info("node re-enrollment refused: disabled", "node_id", existing.ID, "meshnet", existing.Meshnet)
			}
			return nil, ErrNodeDisabled
		}
		existing.HostName = in.Name
		if !existing.NamePinned {
			// An admin rename wins over the node's hostname: without this guard the
			// next daemon restart (which re-registers) would silently undo it.
			// Deduped for the same reason a fresh node's name is: re-registering
			// under a colleague's name would inherit whatever an ACL granted that
			// name (MESH-5).
			existing.Name = dedupeNodeName(in.Name, namesInMeshnet(peers, existing.ID))
		}
		existing.DiscoKey = in.DiscoKey
		if !existing.TagsPinned {
			// Tags come from the (stable) auth key; refresh on re-enroll. An admin's
			// tags win, or the next daemon restart would erase them.
			existing.Tags = in.Tags
		}
		existing.OwnerUserID = in.OwnerUserID
		// Non-empty only. The daemon reports "" whenever it has no Publish-side
		// registration YET — a fresh install whose mesh session comes up before
		// the device row exists, or one whose creds file momentarily won't load.
		// Overwriting unconditionally turned that into a link that appears and
		// disappears across restarts. Once a node has told us its fingerprint,
		// keep it until it tells us a different one.
		if in.DeviceFingerprint != "" {
			existing.DeviceFingerprint = in.DeviceFingerprint
		}
		existing.AdvertisedRoutes = in.AdvertisedRoutes
		if existing.RoutesReviewed {
			// An admin has managed this node: keep their decision, but drop
			// approvals for routes the node no longer claims — a node that stopped
			// advertising a CIDR must stop receiving its traffic.
			existing.ApprovedRoutes = intersectPrefixes(existing.ApprovedRoutes, in.AdvertisedRoutes)
		} else {
			// Never reviewed: behave as before approval existed, so the feature
			// doesn't silently cut subnet routers that work today — except for a
			// CIDR a peer already publishes, which now waits for an admin (MESH-1).
			existing.ApprovedRoutes = autoApprovable(in.AdvertisedRoutes, peers, existing.ID, c.Logger, in.Meshnet)
		}
		// A daemon restart with an edited config is how an alias request changes,
		// so reconcile on the re-enrollment path too — and AFTER the approval
		// lines above, because an alias needs both halves.
		existing.AliasedRoutes = in.AliasedRoutes
		c.applyAliases(ctx, existing)
		if existing.DERPHome == "" { // backfill a home for nodes enrolled before MESH.4
			existing.DERPHome = c.DefaultDERPHome
		}
		stored, err := c.Nodes.Upsert(ctx, existing) // ID != 0 → update in place
		if err != nil {
			return nil, fmt.Errorf("core: update node: %w", err)
		}
		// A daemon restart with an edited config is the NORMAL way a declaration
		// changes, so this has to run on the re-enrollment path too. Best-effort:
		// the machine is already on the mesh, and a registry hiccup must not undo
		// that.
		if err := c.reconcileDeclaredServices(ctx, stored, in.DeclaredServices); err != nil && c.Logger != nil {
			c.Logger.Warn("reconciling declared services failed", "node_id", stored.ID, "err", err)
		}
		if c.Logger != nil {
			c.Logger.Info("node re-registered", "node_id", stored.ID, "meshnet", stored.Meshnet, "overlay", stored.Overlay)
		}
		return stored, nil
	}
	// Quota gate: a genuinely NEW node counts against the meshnet's cap
	// (re-enrollment above is always exempt — it reuses an existing slot). A
	// "seat" is an ACTIVE (non-disabled) node, so an admin-disabled node frees a
	// seat for someone else — we count active nodes, then ask the quota backend
	// whether one more is allowed, BEFORE allocating an address.
	if c.Quota != nil {
		active, _ := seatCounts(peers)
		allowed, limit, reason, err := c.Quota.Admit(ctx, in.Meshnet, active)
		switch {
		case err != nil:
			// Degrade OPEN: a quota backend hiccup must not lock a meshnet out of
			// enrolling. Log and admit (mirrors tunnel-svc's quotaclient).
			if c.Logger != nil {
				c.Logger.Warn("node quota check failed; admitting (degrade open)", "meshnet", in.Meshnet, "err", err)
			}
		case !allowed:
			if c.Logger != nil {
				c.Logger.Info("node enrollment refused: over quota", "meshnet", in.Meshnet, "seats_used", active, "limit", limit)
			}
			return nil, fmt.Errorf("%w: %s", ErrNodeQuotaExceeded, reason)
		}
	}

	// Device approval (MESH.8e-5) applies to genuinely NEW devices only: an
	// existing node keeps what it had, so turning the switch on never parks a
	// fleet that already works.
	approved := true
	if c.Settings != nil {
		set, err := c.Settings.GetSettings(ctx, in.Meshnet)
		if err != nil {
			// Degrade OPEN, like the quota gate: a settings read blip must not stop a
			// device from enrolling. It can still be parked by hand afterwards.
			if c.Logger != nil {
				c.Logger.Warn("settings read failed; admitting device without the approval gate", "meshnet", in.Meshnet, "err", err)
			}
		} else if set.RequireDeviceApproval {
			approved = false
		}
	}

	addr, err := c.IPAM.Allocate(ctx, in.Meshnet)
	if err != nil {
		return nil, fmt.Errorf("core: allocate overlay: %w", err)
	}
	n := &Node{
		Meshnet:          in.Meshnet,
		Name:             dedupeNodeName(in.Name, namesInMeshnet(peers, 0)), // MESH-5
		HostName:         in.Name,
		NodeKey:          in.NodeKey,
		DiscoKey:         in.DiscoKey,
		Tags:             in.Tags,
		OwnerUserID:      in.OwnerUserID,
		AdvertisedRoutes: in.AdvertisedRoutes,
		// Not yet reviewed (see RoutesReviewed), minus anything a peer already
		// publishes — that one waits for an admin (MESH-1).
		ApprovedRoutes:    autoApprovable(in.AdvertisedRoutes, peers, 0, c.Logger, in.Meshnet),
		AliasedRoutes:     in.AliasedRoutes,
		Overlay:           addr,
		DeviceFingerprint: in.DeviceFingerprint,
		Approved:          approved,
		DERPHome:          c.DefaultDERPHome, // deployment home region until the node reports its own
	}
	c.applyAliases(ctx, n)
	stored, err := c.Nodes.Upsert(ctx, n)
	if err != nil {
		// Best-effort: return the address to the pool so a store failure doesn't
		// leak overlay space.
		_ = c.IPAM.Release(ctx, addr)
		return nil, fmt.Errorf("core: persist node: %w", err)
	}
	if err := c.reconcileDeclaredServices(ctx, stored, in.DeclaredServices); err != nil && c.Logger != nil {
		c.Logger.Warn("recording declared services failed", "node_id", stored.ID, "err", err)
	}
	if c.Logger != nil {
		c.Logger.Info("node registered", "node_id", stored.ID, "meshnet", stored.Meshnet, "overlay", stored.Overlay)
	}
	return stored, nil
}

// NetMapFor computes the ACL-filtered network map for one node: every OTHER node
// in its meshnet that the policy allows it to reach, plus the DERP map.
//
// v0: PolicyStore is allow-all, so this is a full mesh minus self. MESH.5 makes
// the Filter call actually cut the set.
func (c *Coordinator) NetMapFor(ctx context.Context, nodeID int64) (*NetMap, error) {
	self, err := c.Nodes.Get(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	// A disabled node gets no map (MESH.8b) — the RPC layer terminates its
	// stream. Returning the sentinel keeps that decision in one place.
	if self.Disabled {
		return nil, ErrNodeDisabled
	}
	// A device awaiting approval enrolls and keeps its address but reaches
	// nothing: it gets an EMPTY peer list rather than an error, so its daemon
	// runs normally and can show "waiting for approval" instead of failing.
	if !self.Approved {
		derp, err := c.DERP.DERPMap(ctx, self.Meshnet)
		if err != nil {
			return nil, fmt.Errorf("core: derp map: %w", err)
		}
		// A pending device still gets its grant. It reaches nobody (empty peer
		// list, and every recipient's WireGuard drops packets from a non-peer), so
		// this grants no access — and issuing here rather than only on approval
		// keeps the node off a hidden dependency on the approval notify firing.
		return &NetMap{Self: *self, DERP: derp, RelayGrant: c.relayGrantFor(ctx, self)}, nil
	}
	all, err := c.nodesWithServices(ctx, self.Meshnet)
	if err != nil {
		return nil, err
	}
	// Use the enriched copy of self so its own declared services ride the netmap
	// (and so an "svc:" rule about self matches the same way it does for peers).
	for _, n := range all {
		if n.ID == self.ID {
			self = n
			break
		}
	}
	candidates := make([]*Node, 0, len(all))
	for _, n := range all {
		// Skip self and any admin-disabled peer — a disabled node is invisible to
		// everyone until re-enabled.
		if n.ID != self.ID && !n.Disabled && n.Approved {
			candidates = append(candidates, n)
		}
	}
	peers, err := c.Policy.Filter(ctx, self.Meshnet, self, candidates)
	if err != nil {
		return nil, fmt.Errorf("core: policy filter: %w", err)
	}
	derp, err := c.DERP.DERPMap(ctx, self.Meshnet)
	if err != nil {
		return nil, fmt.Errorf("core: derp map: %w", err)
	}
	// The packet filter is compiled from the SAME policy document the peer list
	// was filtered with, so the two gates can't disagree about a rule.
	doc, err := c.currentPolicy(ctx, self.Meshnet)
	if err != nil {
		return nil, err
	}
	nm := &NetMap{
		Self:         *self,
		DERP:         derp,
		PacketFilter: c.packetFilterFor(self, peers, doc),
		RelayGrant:   c.relayGrantFor(ctx, self),
	}
	// Alias accounting for Self. `all` is already in hand, so totalling the
	// meshnet costs nothing here — unlike in Register, where it would mean an
	// extra scan on every reconnect.
	nm.UnaliasedRoutes = unaliasedRoutes(self)
	nm.AliasBudgetAddrs = c.aliasBudgetOf(ctx, self.Meshnet)
	for _, n := range all {
		nm.AliasUsedAddrs += AliasSpend(n.RouteAliases)
	}
	for _, p := range peers {
		nm.Peers = append(nm.Peers, *p)
	}
	return nm, nil
}

// nodesWithServices lists a meshnet's nodes with their declared services
// attached. Every ACL evaluation goes through it — netmap filtering, the save
// preview and the access checker — so an "svc:" rule can't mean one thing in the
// preview and another in enforcement. A registry read failure is an error, not
// an empty list: silently dropping services would turn "svc:" rules into rules
// that grant nothing.
func (c *Coordinator) nodesWithServices(ctx context.Context, t MeshnetID) ([]*Node, error) {
	nodes, err := c.Nodes.ListMeshnet(ctx, t)
	if err != nil {
		return nil, fmt.Errorf("core: list meshnet: %w", err)
	}
	if c.Services == nil {
		return nodes, nil
	}
	svcs, err := c.Services.ListServices(ctx, t)
	if err != nil {
		return nil, fmt.Errorf("core: list services: %w", err)
	}
	byNode := make(map[int64][]Service, len(nodes))
	for _, s := range svcs {
		// Only CONFIRMED services are visible to the ACL. A node's own claim must
		// never match a "svc:" rule — that is the whole point of the pending
		// state.
		if !s.Approved {
			continue
		}
		byNode[s.NodeID] = append(byNode[s.NodeID], s)
	}
	for _, n := range nodes {
		n.Services = byNode[n.ID]
	}
	return nodes, nil
}

// SaveACL is the ONE write path for a meshnet's access rules: validate, store,
// then append a revision. Keeping it in core (rather than in the HTTP handler)
// means every caller gets the same guard rails and the same history — the
// history is only trustworthy if it cannot be bypassed.
//
// The revision append is best-effort: history is valuable, but losing it must
// not fail a policy write the admin already confirmed (and which is by then
// live). A failure is logged.
func (c *Coordinator) SaveACL(ctx context.Context, t MeshnetID, doc ACLPolicy, actor string) error {
	if c.ACL == nil {
		return fmt.Errorf("core: acl editing not supported")
	}
	if err := ValidateACLPolicy(doc); err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidACL, err)
	}
	if err := c.ACL.SetACL(ctx, t, doc); err != nil {
		return fmt.Errorf("core: save acl: %w", err)
	}
	if c.ACLRevisions != nil {
		if err := c.ACLRevisions.AppendRevision(ctx, t, doc, actor); err != nil && c.Logger != nil {
			c.Logger.Warn("acl saved but revision not recorded", "meshnet", t, "err", err)
		}
	}
	return nil
}

// ACLRevisionsFor returns a meshnet's saved ACL versions, newest first. Empty
// (not an error) when the build has no revision store.
func (c *Coordinator) ACLRevisionsFor(ctx context.Context, t MeshnetID, limit int) ([]ACLRevision, error) {
	if c.ACLRevisions == nil {
		return nil, nil
	}
	return c.ACLRevisions.ListRevisions(ctx, t, limit)
}

// RenameNode sets a node's MagicDNS name from the admin surface. The name is a
// DNS label peers actually resolve, so it is normalized, validated, and required
// to be unique within the meshnet — two nodes answering to one name is an
// ambiguous resolve (which is the state a fleet of daemons all named "daemon" is
// in today). The rename is PINNED, so the node's next re-registration doesn't
// overwrite it with its hostname.
//
// Returns the updated node so the caller can render it without a re-read. The
// caller is responsible for bumping the meshnet afterwards: peers cache the name
// in their netmap, so they need a fresh push for MagicDNS to follow.
func (c *Coordinator) RenameNode(ctx context.Context, nodeID int64, name string) (*Node, error) {
	name = NormalizeNodeName(name)
	if err := ValidateNodeName(name); err != nil {
		return nil, err
	}
	self, err := c.Nodes.Get(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	if self.Name == name {
		return self, nil // already there; don't churn peers' netmaps
	}
	peers, err := c.Nodes.ListMeshnet(ctx, self.Meshnet)
	if err != nil {
		return nil, fmt.Errorf("core: list meshnet: %w", err)
	}
	for _, p := range peers {
		if p.ID != nodeID && NormalizeNodeName(p.Name) == name {
			return nil, fmt.Errorf("%w: node %d is already named %q", ErrNodeNameTaken, p.ID, name)
		}
	}
	if err := c.Nodes.UpdateName(ctx, nodeID, name); err != nil {
		return nil, fmt.Errorf("core: rename node: %w", err)
	}
	if c.Logger != nil {
		c.Logger.Info("node renamed", "node_id", nodeID, "meshnet", self.Meshnet, "from", self.Name, "to", name)
	}
	self.Name = name
	self.NamePinned = true
	return self, nil
}

// SetNodeTags replaces a node's ACL tags and pins them, so the daemon's next
// registration doesn't undo the change.
//
// Tags are an AUTHORIZATION input — "tag:db" in a rule grants access to whoever
// carries it — which is why a node can never assert its own (core/auth.go) and
// why this is an admin surface. It is scoped to the meshnet for the same reason
// every other node mutation is: an id from another tenant must 404.
func (c *Coordinator) SetNodeTags(ctx context.Context, t MeshnetID, nodeID int64, tags []string) (*Node, error) {
	clean, err := NormalizeNodeTags(tags)
	if err != nil {
		return nil, err
	}
	node, err := c.Nodes.Get(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	if node.Meshnet != t {
		return nil, ErrNodeNotFound
	}
	if err := c.Nodes.SetTags(ctx, nodeID, clean); err != nil {
		return nil, fmt.Errorf("core: set tags: %w", err)
	}
	node.Tags = clean
	node.TagsPinned = true
	if c.Logger != nil {
		c.Logger.Info("node tags set", "node_id", nodeID, "meshnet", t, "tags", clean)
	}
	return node, nil
}

// ErrUnknownDERPRegion is returned by SetDERPHome for a region the published
// DERP map doesn't contain. The RPC layer maps it to InvalidArgument.
var ErrUnknownDERPRegion = errors.New("core: unknown derp region")

// SettingsFor returns a meshnet's switches (defaults when unset / unsupported).
func (c *Coordinator) SettingsFor(ctx context.Context, t MeshnetID) (MeshnetSettings, error) {
	if c.Settings == nil {
		return MeshnetSettings{}, nil
	}
	return c.Settings.GetSettings(ctx, t)
}

// UpdateSettings writes a meshnet's switches. Turning device approval ON
// GRANDFATHERS every node already enrolled: the switch decides who may join from
// now on, and retroactively parking a working fleet would be an outage disguised
// as a security feature.
func (c *Coordinator) UpdateSettings(ctx context.Context, t MeshnetID, in MeshnetSettings) error {
	if c.Settings == nil {
		return fmt.Errorf("core: settings not supported")
	}
	prev, err := c.Settings.GetSettings(ctx, t)
	if err != nil {
		return fmt.Errorf("core: read settings: %w", err)
	}
	// The alias budget is one org's claim on a pool every org shares, so it gets
	// a ceiling here as well as an RBAC gate in the BFFs (audit finding MESH-4):
	// whoever reaches this call, through whichever surface, cannot take the pool.
	if in.AliasAddrBudget > MaxAliasAddrBudget {
		if c.Logger != nil {
			c.Logger.Warn("clamping alias budget to the platform maximum",
				"meshnet", t, "asked", in.AliasAddrBudget, "max", MaxAliasAddrBudget)
		}
		in.AliasAddrBudget = MaxAliasAddrBudget
	}
	if in.AliasAddrBudget < 0 {
		in.AliasAddrBudget = 0 // 0 = DefaultAliasAddrBudget
	}
	if err := c.Settings.SetSettings(ctx, t, in); err != nil {
		return fmt.Errorf("core: save settings: %w", err)
	}
	if in.RequireDeviceApproval && !prev.RequireDeviceApproval {
		nodes, err := c.Nodes.ListMeshnet(ctx, t)
		if err != nil {
			return fmt.Errorf("core: list meshnet: %w", err)
		}
		for _, n := range nodes {
			if n.Approved {
				continue
			}
			if err := c.Nodes.SetApproved(ctx, n.ID, true); err != nil {
				return fmt.Errorf("core: grandfather node %d: %w", n.ID, err)
			}
		}
		if c.Logger != nil {
			c.Logger.Info("device approval enabled; existing devices grandfathered", "meshnet", t, "nodes", len(nodes))
		}
	}
	return nil
}

// DeleteNode removes a device from the meshnet for good: its services go, its
// overlay address is returned to the pool, and it disappears from every peer's
// netmap.
//
// This is NOT a kill switch. A daemon that is still running re-enrolls on its
// next reconcile and comes back as a NEW device (a new id, and whatever address
// the pool hands out) — unless the meshnet requires device approval, where it
// lands in "pending" instead. Disable is what keeps a device out; delete is for
// clearing away machines that are gone. The console says so at the confirm.
func (c *Coordinator) DeleteNode(ctx context.Context, t MeshnetID, nodeID int64) error {
	node, err := c.Nodes.Get(ctx, nodeID)
	if err != nil {
		return err
	}
	// Same cross-tenant guard as every other node mutation: an id from another
	// meshnet must 404, not delete.
	if node.Meshnet != t {
		return ErrNodeNotFound
	}
	// Services first: they are ACL selectors, so an orphaned row would keep
	// granting access to a device that no longer exists.
	if c.Services != nil {
		svcs, err := c.Services.ListServices(ctx, t)
		if err != nil {
			return fmt.Errorf("core: list services: %w", err)
		}
		for _, s := range svcs {
			if s.NodeID != nodeID {
				continue
			}
			if err := c.Services.DeleteService(ctx, s.ID); err != nil && !errors.Is(err, ErrServiceNotFound) {
				return fmt.Errorf("core: delete service %d: %w", s.ID, err)
			}
		}
	}
	if err := c.Nodes.Delete(ctx, nodeID); err != nil {
		return fmt.Errorf("core: delete node: %w", err)
	}
	// Only now is the address safe to reuse. A failure here leaks one address
	// until the next restart re-warms the pool from the surviving nodes, which
	// is recoverable — handing a live address to someone else would not be.
	if c.IPAM != nil && node.Overlay.IsValid() {
		if err := c.IPAM.Release(ctx, node.Overlay); err != nil && c.Logger != nil {
			c.Logger.Warn("node deleted but releasing its overlay failed", "node_id", nodeID, "overlay", node.Overlay, "err", err)
		}
	}
	if c.AliasIPAM != nil {
		for _, ra := range node.RouteAliases {
			if err := c.AliasIPAM.Release(ctx, ra.Alias); err != nil && c.Logger != nil {
				c.Logger.Warn("node deleted but releasing its subnet alias failed",
					"node_id", nodeID, "alias", ra.Alias, "real", ra.Real, "err", err)
			}
		}
	}
	if c.Logger != nil {
		c.Logger.Info("node deleted", "node_id", nodeID, "meshnet", t, "name", node.Name, "overlay", node.Overlay)
	}
	return nil
}

// SetNodeApproved approves (or un-approves) one enrolled device.
func (c *Coordinator) SetNodeApproved(ctx context.Context, t MeshnetID, nodeID int64, approved bool) (*Node, error) {
	node, err := c.Nodes.Get(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	if node.Meshnet != t {
		return nil, ErrNodeNotFound
	}
	if err := c.Nodes.SetApproved(ctx, nodeID, approved); err != nil {
		return nil, fmt.Errorf("core: set approved: %w", err)
	}
	node.Approved = approved
	if c.Logger != nil {
		c.Logger.Info("device approval changed", "node_id", nodeID, "meshnet", t, "approved", approved)
	}
	return node, nil
}

// ApproveRoutes sets which of a node's CLAIMED routes the mesh will actually
// route to it, and marks the node reviewed (so its claims stop being honoured
// automatically from then on). Approving a route the node doesn't claim is
// refused: the list is a decision about claims, not a way to invent them.
func (c *Coordinator) ApproveRoutes(ctx context.Context, t MeshnetID, nodeID int64, approved []netip.Prefix) (*Node, error) {
	node, err := c.Nodes.Get(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	if node.Meshnet != t {
		return nil, ErrNodeNotFound
	}
	for _, r := range approved {
		if !containsPrefix(node.AdvertisedRoutes, r) {
			return nil, fmt.Errorf("%w: %s is not advertised by this node", ErrRouteNotAdvertised, r)
		}
	}
	if err := c.Nodes.UpdateApprovedRoutes(ctx, nodeID, approved); err != nil {
		return nil, fmt.Errorf("core: approve routes: %w", err)
	}
	node.ApprovedRoutes = approved
	node.RoutesReviewed = true
	// Withdrawing approval must also take the alias back: it is an address other
	// nodes hold routes for, and leaving it allocated to a route nobody may use
	// leaks the block until the next restart re-warms the pool.
	if c.applyAliases(ctx, node) {
		if err := c.Nodes.UpdateRouteAliases(ctx, nodeID, node.RouteAliases); err != nil {
			return nil, fmt.Errorf("core: persist route aliases: %w", err)
		}
	}
	if c.Logger != nil {
		c.Logger.Info("node routes reviewed", "node_id", nodeID, "meshnet", t, "approved", len(approved), "advertised", len(node.AdvertisedRoutes))
	}
	return node, nil
}

// ErrRouteNotAdvertised is returned when an approval names a CIDR the node never
// claimed.
var ErrRouteNotAdvertised = errors.New("core: route not advertised by node")

func containsPrefix(list []netip.Prefix, want netip.Prefix) bool {
	for _, p := range list {
		if p == want {
			return true
		}
	}
	return false
}

// intersectPrefixes keeps only the entries of a that are still in b.
func intersectPrefixes(a, b []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range a {
		if containsPrefix(b, p) {
			out = append(out, p)
		}
	}
	return out
}

// SetDERPHome records the relay region a node measured as its closest (MESH.4
// B2b): the node probes every region in the DERP map and reports the fastest,
// replacing the deployment-wide default stamped at registration.
//
// The region is VALIDATED against the map this coordinator publishes, for the
// same reason the coordinator owns the map at all: derp_home is distributed to
// peers as "relay here to reach this node", so a node that could name an
// arbitrary region would send its peers to a relay that doesn't exist (silently
// unreachable) — or park a fabricated label in everyone's console. A node may
// only pick among the relays the coordinator itself offered.
//
// Idempotent: reporting the current home is a no-op (no store write, no netmap
// churn — the report loop repeats every minute).
func (c *Coordinator) SetDERPHome(ctx context.Context, nodeID int64, region string) (changed bool, err error) {
	if region == "" {
		return false, nil // "no measurement yet" — keep whatever home the node has
	}
	self, err := c.Nodes.Get(ctx, nodeID)
	if err != nil {
		return false, err
	}
	if self.DERPHome == region {
		return false, nil
	}
	// The node's OWN meshnet's map. Validating against a shared map would let a
	// node name a region that exists only for some other org — a code it could
	// not otherwise learn, but which would park a foreign label in its peers'
	// netmaps and send them relaying somewhere they have no business.
	derp, err := c.DERP.DERPMap(ctx, self.Meshnet)
	if err != nil {
		return false, fmt.Errorf("core: derp map: %w", err)
	}
	if !derp.HasRegion(region) {
		return false, fmt.Errorf("%w: %q", ErrUnknownDERPRegion, region)
	}
	if err := c.Nodes.UpdateDERPHome(ctx, nodeID, region); err != nil {
		return false, fmt.Errorf("core: update derp home: %w", err)
	}
	if c.Logger != nil {
		c.Logger.Info("node derp home updated (client-measured)", "node_id", nodeID, "from", self.DERPHome, "to", region)
	}
	return true, nil
}

// SeatUsage is a meshnet's mesh-node seat accounting (MESH.8d): how many seats
// are occupied (Active, non-disabled nodes), how many nodes are parked
// (Disabled, not consuming a seat), the total, and the plan's seat allowance
// (Limit; -1 = unlimited). It's the source the account/billing view reflects.
type SeatUsage struct {
	Meshnet  MeshnetID `json:"meshnet"`
	Total    int       `json:"nodes_total"`
	Active   int       `json:"seats_used"`
	Disabled int       `json:"seats_disabled"`
	Limit    int       `json:"seats_limit"`
}

// SeatUsage reports a meshnet's seat accounting. Limit comes from the quota
// backend (the same Admit path used to gate enrollment, read for its limit);
// nil quota or a backend error reports -1 (unlimited/unknown) rather than
// failing — a usage read must never 500 the account view.
func (c *Coordinator) SeatUsage(ctx context.Context, t MeshnetID) (SeatUsage, error) {
	nodes, err := c.Nodes.ListMeshnet(ctx, t)
	if err != nil {
		return SeatUsage{}, fmt.Errorf("core: list meshnet: %w", err)
	}
	active, disabled := seatCounts(nodes)
	limit := -1
	if c.Quota != nil {
		if _, lim, _, err := c.Quota.Admit(ctx, t, active); err == nil {
			limit = lim
		}
	}
	return SeatUsage{Meshnet: t, Total: len(nodes), Active: active, Disabled: disabled, Limit: limit}, nil
}

// seatCounts splits a node set into active (seat-occupying) and disabled counts.
func seatCounts(nodes []*Node) (active, disabled int) {
	for _, n := range nodes {
		if n.Disabled {
			disabled++
		} else {
			active++
		}
	}
	return active, disabled
}

// UpdateDeclarationsInput is what a node asserts about ITSELF and may change
// without re-enrolling. Deliberately narrow: everything an admin can pin (name,
// tags, route approvals) is a decision ABOUT the node and stays out.
type UpdateDeclarationsInput struct {
	Meshnet MeshnetID
	NodeKey meshproto.NodeKey
	// DeclaredServices replaces the node's declaration set wholesale, through
	// the SAME reconcile the registration path uses — so a console-added or
	// admin-confirmed service is treated identically either way.
	DeclaredServices []Service
	// DeviceFingerprint is applied only when non-empty. "" is what a node
	// reports both when it has no Publish-side registration yet and when its
	// config momentarily won't read; erasing a good value over the second is a
	// self-inflicted outage of the console's client link.
	DeviceFingerprint string
}

// UpdateDeclarations records new declarations for an already-enrolled node.
//
// The point is what it does NOT do: no IPAM, no key rotation, no netmap
// invalidation of this node's own session. Editing a service list used to
// require a full re-enrollment, which tore down WireGuard and re-punched every
// path for a change that moves no addresses.
//
// Returns ErrNodeNotFound when the key isn't enrolled here, so the caller can
// fall back to Register rather than silently succeeding at nothing.
func (c *Coordinator) UpdateDeclarations(ctx context.Context, in UpdateDeclarationsInput) (*Node, error) {
	if in.NodeKey.IsZero() {
		return nil, fmt.Errorf("core: update declarations: node_key is zero")
	}
	existing, err := c.Nodes.FindByKey(ctx, in.Meshnet, in.NodeKey)
	if err != nil || existing == nil {
		return nil, ErrNodeNotFound
	}
	// A disabled node is refused here for the same reason it is refused
	// re-enrollment: an admin took it out of the mesh, and its own reconnect
	// loop must not be able to keep editing what the mesh knows about it.
	if existing.Disabled {
		return nil, ErrNodeDisabled
	}
	if in.DeviceFingerprint != "" {
		existing.DeviceFingerprint = in.DeviceFingerprint
	}
	stored, err := c.Nodes.Upsert(ctx, existing)
	if err != nil {
		return nil, fmt.Errorf("core: update node: %w", err)
	}
	// Same reconcile as registration — one implementation of "what a declaration
	// means", so the two paths cannot drift on validation, confirmation state or
	// the console-owned entries.
	if err := c.reconcileDeclaredServices(ctx, stored, in.DeclaredServices); err != nil {
		return nil, fmt.Errorf("core: reconcile declared services: %w", err)
	}
	if c.Logger != nil {
		c.Logger.Info("node declarations updated",
			"node_id", stored.ID, "meshnet", stored.Meshnet, "services", len(in.DeclaredServices))
	}
	return stored, nil
}

// applyAliases brings node.RouteAliases in line with what the node asks for and
// an admin approved, releasing whatever falls out. Reports whether the set
// changed, so a caller that must persist it separately can skip a no-op write.
//
// Failures are logged, never returned: a subnet too large to alias, or an
// exhausted pool, must not keep a node off the mesh. That route simply publishes
// under its real CIDR — which is where it was before this feature existed.
func (c *Coordinator) applyAliases(ctx context.Context, node *Node) bool {
	keep, release, err := reconcileAliases(ctx, c.AliasIPAM, node.Meshnet, node, c.aliasBudgetFor(ctx, node))
	if err != nil && c.Logger != nil {
		c.Logger.Warn("could not alias every requested subnet; those routes publish under their real CIDR",
			"node_id", node.ID, "meshnet", node.Meshnet, "err", err)
	}
	for _, alias := range release {
		if c.AliasIPAM == nil {
			break
		}
		if rerr := c.AliasIPAM.Release(ctx, alias); rerr != nil && c.Logger != nil {
			c.Logger.Warn("releasing a subnet alias failed", "node_id", node.ID, "alias", alias, "err", rerr)
		}
	}
	changed := len(release) > 0 || !sameAliases(node.RouteAliases, keep)
	node.RouteAliases = keep
	return changed
}

func sameAliases(a, b []RouteAlias) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// aliasBudgetFor is how much alias pool space THIS node may occupy: the
// meshnet's budget less what its OTHER nodes already hold.
//
// Skips both reads when the node needs nothing new. A daemon re-registering with
// unchanged routes is the overwhelmingly common call, and it must not cost a
// settings read plus a scan of every node in the meshnet.
func (c *Coordinator) aliasBudgetFor(ctx context.Context, node *Node) int {
	if c.AliasIPAM == nil || !needsNewAlias(node) {
		return math.MaxInt // nothing will be allocated; the budget cannot bind
	}
	budget := c.aliasBudgetOf(ctx, node.Meshnet)
	// What the meshnet's OTHER nodes hold. A store that cannot list is not a
	// reason to refuse service, but it IS a reason not to hand out more: fall
	// back to the node's current spend, which grants nothing new.
	peers, err := c.Nodes.ListMeshnet(ctx, node.Meshnet)
	if err != nil {
		if c.Logger != nil {
			c.Logger.Warn("cannot total the meshnet's alias usage; granting no new aliases this round",
				"meshnet", node.Meshnet, "err", err)
		}
		return AliasSpend(node.RouteAliases)
	}
	others := 0
	for _, p := range peers {
		if p == nil || p.ID == node.ID {
			continue
		}
		others += AliasSpend(p.RouteAliases)
	}
	if remaining := budget - others; remaining > 0 {
		return remaining
	}
	return 0
}

// needsNewAlias reports whether any route this node wants aliased does not
// already have one.
func needsNewAlias(node *Node) bool {
	held := make(map[netip.Prefix]bool, len(node.RouteAliases))
	for _, ra := range node.RouteAliases {
		held[ra.Real.Masked()] = true
	}
	for _, real := range wantedAliases(node) {
		if !held[real] {
			return true
		}
	}
	return false
}

// aliasBudgetOf is a meshnet's alias budget in addresses: its own setting, or
// the built-in default when unset or unreadable. Never returns 0 by accident —
// a settings hiccup must not look like "you may have no aliases".
func (c *Coordinator) aliasBudgetOf(ctx context.Context, t MeshnetID) int {
	if c.Settings == nil {
		return DefaultAliasAddrBudget
	}
	s, err := c.Settings.GetSettings(ctx, t)
	if err != nil || s.AliasAddrBudget <= 0 {
		return DefaultAliasAddrBudget
	}
	return s.AliasAddrBudget
}
