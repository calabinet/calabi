package core

import (
	"context"
	"errors"
	"net/netip"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// ErrNodeNotFound is returned by NodeStore.Get for an unknown id.
var ErrNodeNotFound = errors.New("core: node not found")

// RegistrationPeerStore optionally projects only the fields used by registration:
// ID, Name, Disabled, OwnerUserID, ApprovedRoutes, RealRoutes and RouteAliases.
// These incomplete nodes must never be used for maps, authentication or writes.
type RegistrationPeerStore interface {
	ListRegistrationPeers(context.Context, MeshnetID) ([]*Node, error)
}

// RegistrationNameStore reads all other names, including disabled nodes. Only
// route-free existing registrations can use this projection; no policy state
// is cached and name normalization still happens in the common Go code.
type RegistrationNameStore interface {
	ListRegistrationNames(context.Context, MeshnetID, int64) ([]string, error)
}

// RegistrationTouchStore can avoid rewriting identical registration state.
// It must only touch bookkeeping, scope the update to the same live identity,
// and return a freshly read node. Policy/declaration changes are not skipped.
type RegistrationTouchStore interface {
	TouchRegistration(context.Context, *Node) (*Node, error)
}

func (c *Coordinator) registrationNames(ctx context.Context, t MeshnetID, id int64) (map[string]bool, error) {
	if s, ok := c.Nodes.(RegistrationNameStore); ok {
		names, err := s.ListRegistrationNames(ctx, t, id)
		if err != nil {
			return nil, err
		}
		out := make(map[string]bool, len(names))
		for _, name := range names {
			if n := NormalizeNodeName(name); n != "" {
				out[n] = true
			}
		}
		return out, nil
	}
	peers, err := c.registrationPeers(ctx, t)
	return namesInMeshnet(peers, id), err
}

func (c *Coordinator) registrationPeers(ctx context.Context, t MeshnetID) ([]*Node, error) {
	if s, ok := c.Nodes.(RegistrationPeerStore); ok {
		return s.ListRegistrationPeers(ctx, t)
	}
	return c.Nodes.ListMeshnet(ctx, t)
}

// NodeStore persists nodes. The platform build backs it with the tenant DB +
// Device registry; the self-hosted build backs it with the in-memory MemNodeStore.
type NodeStore interface {
	// Upsert inserts or updates a node. On insert, n.ID is assigned by the store.
	Upsert(ctx context.Context, n *Node) (*Node, error)
	// Get returns a node by id, or ErrNodeNotFound.
	Get(ctx context.Context, id int64) (*Node, error)
	// FindByKey returns the node in meshnet t with the given node key, or
	// ErrNodeNotFound. Register uses it for idempotent re-enrollment: a node
	// reconnecting with the same key keeps its id + overlay instead of leaking a
	// new address and leaving a stale peer in everyone's netmap.
	FindByKey(ctx context.Context, t MeshnetID, key meshproto.NodeKey) (*Node, error)
	// ListMeshnet returns every node in a meshnet (caller filters by ACL).
	ListMeshnet(ctx context.Context, t MeshnetID) ([]*Node, error)
	// UpdateEndpoints replaces a node's discovered endpoints.
	UpdateEndpoints(ctx context.Context, id int64, eps []netip.AddrPort) error
	// UpdateApprovedRoutes records which advertised routes an admin allowed, and
	// marks the node reviewed.
	UpdateApprovedRoutes(ctx context.Context, id int64, routes []netip.Prefix, realRoutes ...[]netip.Prefix) error
	// UpdateRouteAliases records the stand-in prefixes allocated for this node's
	// aliased subnet routes. Separate from UpdateApprovedRoutes because an
	// approval change reconciles them as a consequence, and the two writes must
	// not be able to disagree about which routes the aliases belong to.
	UpdateRouteAliases(ctx context.Context, id int64, aliases []RouteAlias) error
	// UpdateName sets an ADMIN-chosen node name and pins it, so re-registration
	// stops following the node's hostname. Validated + uniqueness-checked by
	// Coordinator.RenameNode before it gets here.
	UpdateName(ctx context.Context, id int64, name string) error
	// UpdateDERPHome records the relay region a node measured as its closest.
	// Validated against the published DERP map before it gets here.
	UpdateDERPHome(ctx context.Context, id int64, region string) error
	// Delete removes a node permanently; ErrNodeNotFound if unknown. The caller
	// releases the overlay address AFTER this succeeds — releasing first could
	// hand the address to a new node while this one still answers to it.
	Delete(ctx context.Context, id int64) error
	// SetTags replaces a node's ACL tags and pins them (see Node.TagsPinned).
	SetTags(ctx context.Context, id int64, tags []string) error
	// SetApproved flips device approval.
	SetApproved(ctx context.Context, id int64, approved bool) error
	// SetDisabled flips a node's admin kill switch. Returns
	// ErrNodeNotFound for an unknown id.
	SetDisabled(ctx context.Context, id int64, disabled bool) error
	// SetSignedOut records a device's sign-out (Node.SignedOut). Returns
	// ErrNodeNotFound for an unknown id.
	SetSignedOut(ctx context.Context, id int64, signedOut bool) error
}

// PolicyStore compiles a meshnet's ACL into the peer set a given node may reach.
//
// It started as allow-all; the ACL engine (groups / tags /
// src->dst:port) now filters the candidate set. Keeping the interface
// here from day one meant the netmap code never changed when ACLs landed.
//
// Filter cuts only the peer list. The packet filter compiles from the document
// behind it, so a new implementation has to be readable by policyDocument too;
// until it is, every netmap that falls back to it fails rather than open.
type PolicyStore interface {
	// Filter returns the subset of candidates that self is allowed to reach.
	Filter(ctx context.Context, t MeshnetID, self *Node, candidates []*Node) ([]*Node, error)
}

// IPAM allocates stable overlay addresses from the node half of 100.64.0.0/10
// per meshnet.
type IPAM interface {
	Allocate(ctx context.Context, t MeshnetID) (netip.Addr, error)
	Release(ctx context.Context, addr netip.Addr) error
}

// AliasIPAM allocates stand-in PREFIXES for subnet routes whose real addresses
// would collide with a consumer's own LAN — the same shape as IPAM, one level
// up. The returned prefix is the same size as real, so the subnet router can
// rewrite 1:1. See core.MemAliasIPAM.
//
// Optional on the Coordinator: a nil AliasIPAM means this deployment does not
// offer aliasing, and every alias request is simply not granted (the route is
// still published under its real CIDR, exactly as before the feature existed).
type AliasIPAM interface {
	Allocate(ctx context.Context, t MeshnetID, real netip.Prefix) (netip.Prefix, error)
	Release(ctx context.Context, alias netip.Prefix) error
}

// DERPMapSource supplies the relay directory a given meshnet should use.
// Platform build sources it from the fleet/config; self-hosted build serves a
// static file.
//
// The meshnet parameter is what makes self-hosted relays possible: an org's
// map is the platform's regions PLUS the relays that org runs itself, and one
// org's relays must never appear in another's. A relay sees no plaintext, but it
// does see the metadata — who talks to whom, how much, when — so handing org B's
// map an entry from org A would hand A a picture of B's traffic. Implementations
// that have no per-org relays (StaticDERP, self-hosted) ignore the parameter and
// return the same map to everyone, which is exactly today's behaviour.
type DERPMapSource interface {
	DERPMap(ctx context.Context, t MeshnetID) (DERPMap, error)
}
