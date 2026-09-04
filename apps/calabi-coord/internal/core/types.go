// Package core is the coordinator's edition-agnostic brain: netmap computation,
// the store/policy/IPAM interfaces, and the domain types. It has ZERO
// control-plane dependencies (no pkg/api) — so this exact package is what the
// community coordinator (MESH.9) ships. The platform build wraps these
// interfaces with multi-tenant / billing / SSO stores; the community build
// wires the in-memory / file-backed stubs in this file. See the wire_*.go seam
// in cmd/calabi-coord and
package core

import (
	"net/netip"
	"time"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// MeshnetID identifies a mesh network. It equals the org id: one org = one
// meshnet.
type MeshnetID int64

// Node is a device enrolled in a meshnet.
type Node struct {
	ID      int64
	Meshnet MeshnetID
	Name    string // MagicDNS label — what peers resolve; admin-settable (see nodename.go)
	// HostName is the name the NODE reports at registration (its hostname). It is
	// refreshed on every re-register and is only informational: it tells an admin
	// which machine a renamed node is, and it seeds Name for a fresh node.
	HostName string
	// NamePinned marks a name an admin set from the console. Registration then
	// stops overwriting Name with the node's hostname — otherwise the next daemon
	// reconnect (every restart) would silently undo the rename.
	NamePinned bool
	NodeKey    meshproto.NodeKey
	DiscoKey   meshproto.DiscoKey
	Overlay    netip.Addr       // allocated 100.64.x.x /32
	Endpoints  []netip.AddrPort // discovered candidate endpoints (local + STUN)
	DERPHome   string           // region code of the node's home relay
	// AdvertisedRoutes are the subnet-router CIDRs this node CLAIMS it can
	// forward to (MESH.7). A claim alone routes nothing.
	AdvertisedRoutes []netip.Prefix
	// ApprovedRoutes is the subset an admin allowed; only these ride in peers'
	// allowed_ips. Approving a route hands this node other nodes' traffic for
	// that CIDR, which is why it is an admin decision and not a node's own.
	ApprovedRoutes []netip.Prefix
	// RoutesReviewed records that an admin has managed this node's routes at
	// least once. Until then the node keeps the pre-approval behaviour (claims
	// are honoured), so shipping approval doesn't cut every subnet router that
	// works today — see Coordinator.Register.
	RoutesReviewed bool
	// Services are what this node declares it offers (MESH.8e-4). Populated when
	// a netmap / ACL evaluation is computed (see nodesWithServices) — NOT stored
	// on the node row; the registry is its own table.
	Services []Service
	// OwnerUserID is the human whose key enrolled this node (see Identity.UserID).
	// 0 for a node enrolled with an unattributed key. Refreshed on every
	// re-registration: whoever installed it last owns it.
	OwnerUserID int64
	// Tags group nodes for ACL selectors ("tag:server"). Two sources: the auth
	// key (community coord's config; the node NEVER self-asserts them) and an
	// admin setting them in the console. The platform's identity service
	// carries none, so on SaaS the console is the only source.
	Tags []string
	// TagsPinned means an admin set the tags here, so re-registration must not
	// overwrite them from the auth key. Without it every daemon restart would
	// wipe them on the platform build, where the key carries no tags at all —
	// the same trap NamePinned exists for.
	TagsPinned bool
	// DeviceFingerprint is the daemon's per-install id, SELF-REPORTED. It is a
	// display-only hint that lets the console link a mesh device to its client
	// record; nothing here or downstream authorizes on it. Empty when the
	// daemon has no device registration (community coord, standalone client).
	DeviceFingerprint string
	// Approved is device approval (MESH.8e-5): a node enrolled while the meshnet
	// requires approval starts false and reaches nothing until an admin says yes.
	// Defaults TRUE everywhere else, so turning the switch on never retroactively
	// parks devices that already work.
	Approved bool
	// Disabled is an admin kill switch (MESH.8b): a disabled node is dropped
	// from every peer's netmap and refused on (re)register, so it can neither be
	// reached nor rejoin until re-enabled. Set out-of-band by the admin surface,
	// never by the node itself; preserved across the node's re-enrollment.
	Disabled  bool
	CreatedAt time.Time
	LastSeen  time.Time
}

// NetMap is the ACL-filtered view of a meshnet handed to one node. Peers the
// ACL denies are simply absent (first isolation layer).
type NetMap struct {
	Self  Node
	Peers []Node
	DERP  DERPMap
	// PacketFilter is what Self enforces on INBOUND traffic (MESH.5b): compiled
	// from the meshnet's ACL for this node specifically. The peer list above is
	// the host-level gate; this is the narrower port-level one behind it.
	PacketFilter []FilterRule
	// RelayGrant is Self's signed authorization to use relays (R0'), opaque to
	// everyone between here and the relay. Empty when this coordinator issues no
	// grants — relays must then not require them. See relaygrant.go.
	RelayGrant []byte
	// MagicDNS records land here in MESH.6.
}

// DERPMap is the region->relay directory distributed to nodes.
type DERPMap struct {
	Regions []DERPRegion
}

// HasRegion reports whether the map contains a region with this code — the check
// that keeps a node from naming a relay the coordinator never published
// (see Coordinator.SetDERPHome).
func (m DERPMap) HasRegion(code string) bool {
	for _, r := range m.Regions {
		if r.Code == code {
			return true
		}
	}
	return false
}

// DERPRegion is one geographic relay region (reuses the edge fleet footprint).
type DERPRegion struct {
	Code  string // "lax", "sgp", ...
	Nodes []DERPNode
}

// DERPNode is a single calabi-derp relay endpoint.
type DERPNode struct {
	HostName string
	DERPPort int
	STUNPort int
}
