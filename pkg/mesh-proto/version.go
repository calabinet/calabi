package meshproto

// ProtocolVersion is the mesh coordination + relay protocol version negotiated
// between a node, the coordinator, and the DERP relays.
//
// It is DRAFT (0) and may change freely until the community coordinator ships
// (MESH.9). From that point it is frozen into a backward-compatible contract:
// a node and a (possibly self-hosted) coordinator negotiate the highest common
// version via Capabilities. 条件3.
const ProtocolVersion uint32 = 0

// Capability is a coarse feature flag exchanged at handshake so a newer client
// and an older (self-hosted) coordinator — or vice versa — can agree on a
// working subset without a hard version match. v0 defines none; MESH.4+ will
// add e.g. CapHolePunch, CapMagicDNS, CapSubnetRoutes.
type Capability string

// Capabilities is the set a peer advertises. Intersection = the working subset.
type Capabilities []Capability

// Supports reports whether c advertises cap.
func (c Capabilities) Supports(cap Capability) bool {
	for _, x := range c {
		if x == cap {
			return true
		}
	}
	return false
}
