package core

import (
	"context"
	"errors"
	"net/netip"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// ErrNodeNotFound is returned by NodeStore.Get for an unknown id.
var ErrNodeNotFound = errors.New("core: node not found")

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
	// UpdateEndpoints replaces a node's discovered endpoints (MESH.4).
	UpdateEndpoints(ctx context.Context, id int64, eps []netip.AddrPort) error
	// UpdateApprovedRoutes records which advertised routes an admin allowed, and
	// marks the node reviewed.
	UpdateApprovedRoutes(ctx context.Context, id int64, routes []netip.Prefix) error
	// UpdateName sets an ADMIN-chosen node name and pins it, so re-registration
	// stops following the node's hostname. Validated + uniqueness-checked by
	// Coordinator.RenameNode before it gets here.
	UpdateName(ctx context.Context, id int64, name string) error
	// UpdateDERPHome records the relay region a node measured as its closest
	// (MESH.4 B2b). Validated against the published DERP map before it gets here.
	UpdateDERPHome(ctx context.Context, id int64, region string) error
	// Delete removes a node permanently; ErrNodeNotFound if unknown. The caller
	// releases the overlay address AFTER this succeeds — releasing first could
	// hand the address to a new node while this one still answers to it.
	Delete(ctx context.Context, id int64) error
	// SetTags replaces a node's ACL tags and pins them (see Node.TagsPinned).
	SetTags(ctx context.Context, id int64, tags []string) error
	// SetApproved flips device approval (MESH.8e-5).
	SetApproved(ctx context.Context, id int64, approved bool) error
	// SetDisabled flips a node's admin kill switch (MESH.8b). Returns
	// ErrNodeNotFound for an unknown id.
	SetDisabled(ctx context.Context, id int64, disabled bool) error
}

// PolicyStore compiles a meshnet's ACL into the peer set a given node may reach.
//
// v0 (MESH.1) returns allow-all. MESH.5 replaces this with a real ACL engine
// (groups / tags / src->dst:port) that filters the candidate set. Keeping the
// interface here from day one means the netmap code never changes when ACLs land.
type PolicyStore interface {
	// Filter returns the subset of candidates that self is allowed to reach.
	Filter(ctx context.Context, t MeshnetID, self *Node, candidates []*Node) ([]*Node, error)
}

// IPAM allocates stable overlay addresses from 100.64.0.0/10 per meshnet.
type IPAM interface {
	Allocate(ctx context.Context, t MeshnetID) (netip.Addr, error)
	Release(ctx context.Context, addr netip.Addr) error
}

// DERPMapSource supplies the relay directory a given meshnet should use.
// Platform build sources it from the fleet/config; self-hosted build serves a
// static file.
//
// The meshnet parameter is what makes self-hosted relays possible (R1): an org's
// map is the platform's regions PLUS the relays that org runs itself, and one
// org's relays must never appear in another's. A relay sees no plaintext, but it
// does see the metadata — who talks to whom, how much, when — so handing org B's
// map an entry from org A would hand A a picture of B's traffic. Implementations
// that have no per-org relays (StaticDERP, self-hosted) ignore the parameter and
// return the same map to everyone, which is exactly today's behaviour.
type DERPMapSource interface {
	DERPMap(ctx context.Context, t MeshnetID) (DERPMap, error)
}
