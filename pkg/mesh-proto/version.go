package meshproto

// ProtocolVersion is the mesh coordination + relay protocol version negotiated
// between a node, the coordinator, and the DERP relays.
//
// 0 was the draft. 1 existed only on an unreleased branch. 2 (2026-09-10):
// registration proves possession of the node private key
// (GetRegisterChallenge + register_proof) and returns a session token that
// every later node-scoped call carries. A coordinator refuses to enroll a node
// below 2 (security audit 1-C).
//
// A node and a (possibly self-hosted) coordinator negotiate the highest common
// version via Capabilities.
const ProtocolVersion uint32 = 2

// Capability is a coarse feature flag exchanged at handshake so a newer client
// and an older (self-hosted) coordinator — or vice versa — can agree on a
// working subset without a hard version match. v0 defines none; MESH.4+ will
// add e.g. CapHolePunch, CapMagicDNS, CapSubnetRoutes.
type Capability string

// CapNodeReauth: once enrolled, a node may register again by proving it holds
// its node key, without presenting the auth key it enrolled with
// (GetRegisterChallengeRequest.node_id / RegisterNodeRequest.node_id). A node
// must see it in the coordinator's answer before it relies on it — above all
// before it forgets an auth key.
const CapNodeReauth Capability = "node_reauth"

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
