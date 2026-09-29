package meshproto

// TLS on a relay's data port.
//
// A relay speaks TLS and the plaintext protocol on the same port, told apart by
// the first byte a node sends: a TLS ClientHello record starts with 0x16, the
// plaintext protocol with ClientInfo's frame type, 0x01. The relay map says
// which relays speak TLS and how a node checks their certificate
// (meshpb.DERPNodeTLS); these are the names both ends use for that.

// DERPALPN is the application protocol a relay's TLS carries: the DERP frames
// of this package. A name of its own rather than the edge control listener's,
// so a node that reached the wrong port fails the handshake instead of speaking
// the wrong protocol to whatever answered.
const DERPALPN = "calabi-derp/1"

// How a node checks a relay's certificate — the ways it already checks an edge.
const (
	// RelayTrustPlatform: the edge CA compiled into the client, and the relay's
	// host name. calabi.net's relays, the platform's and the ones organizations
	// run themselves; a self-hosted coordinator never hands it out, and a node
	// signed in to one never accepts it.
	RelayTrustPlatform = "platform"
	// RelayTrustSystem: the device's own roots and the host name — a relay with
	// a certificate from a public CA.
	RelayTrustSystem = "system"
	// RelayTrustPin: the certificate's fingerprint (CertPin) is one of the pins
	// listed with it.
	RelayTrustPin = "pin"
)
