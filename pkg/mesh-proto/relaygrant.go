package meshproto

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Relay grants (R0′). A grant is the coordinator's signed statement that one
// node may use relays: "I authorize node K of meshnet M, scope S, until T".
// The coordinator hands it to the node in its netmap; the node presents it when
// it connects to a relay; the relay verifies it with the coordinator's PUBLIC
// key, which it holds as static configuration.
//
// That last part is the point: a relay validates a grant WITHOUT talking to the
// control plane. calabi-derp keeps its defining property — it forwards opaque
// ciphertext and depends on nothing — while the control plane still decides who
// may use it.
//
// A grant on its own is NOT sufficient to connect: it is a static blob, so
// anyone who observes one could replay it. It is always presented together with
// a proof of possession of the node's private key, bound to a relay-chosen
// nonce (derpauth.go). The grant answers "who authorized this, until when, for
// which relays"; the proof answers "are you actually that node". Both are
// required —
//
// Wire format (fixed 120 bytes), signed bytes first:
//
//	[6]  magic "calaG1"        -- domain separation: a coordinator signature over
//	[1]  version                  anything else can never parse as a grant
//	[32] node key
//	[8]  meshnet id            (big endian, signed)
//	[1]  scope
//	[8]  expiry, unix seconds  (big endian, signed)
//	----------------------------- above is what gets signed
//	[64] ed25519 signature

// RelayScope says WHICH relays a grant is good for. It exists so that an org
// over its traffic quota can keep using the relays it pays for itself while
// losing the platform's: the coordinator downgrades the scope instead of
// withholding the grant entirely.
type RelayScope uint8

const (
	// RelayScopeInvalid is the zero value; never issued.
	RelayScopeInvalid RelayScope = 0
	// RelayScopeAll permits every relay — the normal case.
	RelayScopeAll RelayScope = 1
	// RelayScopeSelfHosted permits only relays the org runs itself. Issued when
	// the org is over its monthly traffic cap: its own VPS bandwidth is its own
	// business, the platform's is not.
	RelayScopeSelfHosted RelayScope = 2
)

func (s RelayScope) String() string {
	switch s {
	case RelayScopeAll:
		return "all"
	case RelayScopeSelfHosted:
		return "self-hosted"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(s))
	}
}

// RelayKind is what a relay node itself is, from its own static configuration.
// A relay compares its kind against a grant's scope to decide whether to accept
// the connection.
type RelayKind uint8

const (
	// RelayKindPlatform is a relay the platform runs.
	RelayKindPlatform RelayKind = iota
	// RelayKindSelfHosted is a relay an org runs on its own machine.
	RelayKindSelfHosted
)

func (k RelayKind) String() string {
	if k == RelayKindSelfHosted {
		return "self-hosted"
	}
	return "platform"
}

// Permits reports whether a grant with this scope may be used on a relay of the
// given kind.
func (s RelayScope) Permits(k RelayKind) bool {
	switch s {
	case RelayScopeAll:
		return true
	case RelayScopeSelfHosted:
		return k == RelayKindSelfHosted
	default:
		// An unknown scope from a NEWER coordinator must not be read as
		// permission. Fail closed: the operator upgrades the relay.
		return false
	}
}

// RelayGrant is a decoded grant.
type RelayGrant struct {
	// Node is the node key the grant authorizes. A relay MUST check this against
	// the key the connection claims; without that check a grant issued for one
	// node would authorize a connection claiming to be another.
	Node NodeKey
	// Meshnet is the org the node belongs to. Relays don't act on it (they have
	// no concept of an org); it is here so a relay's logs can be correlated with
	// the control plane during an incident.
	Meshnet int64
	Scope   RelayScope
	Expiry  time.Time
}

var relayGrantMagic = [6]byte{'c', 'a', 'l', 'a', 'G', '1'}

const (
	relayGrantVersion = 1
	// relayGrantSignedLen is magic + version + key + meshnet + scope + expiry.
	relayGrantSignedLen = 6 + 1 + KeyLen + 8 + 1 + 8
	// RelayGrantLen is the full encoded length, signature included.
	RelayGrantLen = relayGrantSignedLen + ed25519.SignatureSize
)

var (
	// ErrGrantMalformed is returned for a blob that isn't a grant at all.
	ErrGrantMalformed = errors.New("meshproto: malformed relay grant")
	// ErrGrantSignature is returned when the signature doesn't verify under the
	// supplied coordinator key.
	ErrGrantSignature = errors.New("meshproto: relay grant signature invalid")
	// ErrGrantExpired is returned for a grant past its expiry.
	ErrGrantExpired = errors.New("meshproto: relay grant expired")
)

// relayGrantSignedBytes lays out the signed prefix. Shared by sign and verify so
// the two can never disagree about what is covered by the signature.
func relayGrantSignedBytes(g RelayGrant) []byte {
	b := make([]byte, relayGrantSignedLen)
	copy(b[0:6], relayGrantMagic[:])
	b[6] = relayGrantVersion
	copy(b[7:7+KeyLen], g.Node[:])
	binary.BigEndian.PutUint64(b[7+KeyLen:], uint64(g.Meshnet))
	b[7+KeyLen+8] = byte(g.Scope)
	binary.BigEndian.PutUint64(b[7+KeyLen+9:], uint64(g.Expiry.Unix()))
	return b
}

// SignRelayGrant encodes and signs a grant with the coordinator's private key.
func SignRelayGrant(priv ed25519.PrivateKey, g RelayGrant) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("meshproto: sign relay grant: bad key size %d", len(priv))
	}
	if g.Scope == RelayScopeInvalid {
		return nil, fmt.Errorf("meshproto: sign relay grant: scope not set")
	}
	if g.Node.IsZero() {
		return nil, fmt.Errorf("meshproto: sign relay grant: node key not set")
	}
	signed := relayGrantSignedBytes(g)
	out := make([]byte, 0, RelayGrantLen)
	out = append(out, signed...)
	out = append(out, ed25519.Sign(priv, signed)...)
	return out, nil
}

// ParseRelayGrant decodes a grant WITHOUT verifying anything. Callers that make
// an access decision must use VerifyRelayGrant instead; this exists for logging
// and for tests.
func ParseRelayGrant(blob []byte) (RelayGrant, error) {
	var g RelayGrant
	if len(blob) != RelayGrantLen {
		return g, fmt.Errorf("%w: length %d, want %d", ErrGrantMalformed, len(blob), RelayGrantLen)
	}
	if string(blob[0:6]) != string(relayGrantMagic[:]) {
		return g, fmt.Errorf("%w: bad magic", ErrGrantMalformed)
	}
	if blob[6] != relayGrantVersion {
		return g, fmt.Errorf("%w: version %d", ErrGrantMalformed, blob[6])
	}
	copy(g.Node[:], blob[7:7+KeyLen])
	g.Meshnet = int64(binary.BigEndian.Uint64(blob[7+KeyLen:]))
	g.Scope = RelayScope(blob[7+KeyLen+8])
	g.Expiry = time.Unix(int64(binary.BigEndian.Uint64(blob[7+KeyLen+9:])), 0).UTC()
	return g, nil
}

// VerifyRelayGrant parses a grant, checks its signature under pub, and checks it
// has not expired as of now. It does NOT check the node key or the scope — the
// caller knows which node is claiming it and what kind of relay it is, and both
// checks are mandatory. See relay.Hub for the full sequence.
func VerifyRelayGrant(pub ed25519.PublicKey, blob []byte, now time.Time) (RelayGrant, error) {
	g, err := ParseRelayGrant(blob)
	if err != nil {
		return g, err
	}
	if len(pub) != ed25519.PublicKeySize {
		return g, fmt.Errorf("meshproto: verify relay grant: bad key size %d", len(pub))
	}
	if !ed25519.Verify(pub, blob[:relayGrantSignedLen], blob[relayGrantSignedLen:]) {
		return g, ErrGrantSignature
	}
	if now.After(g.Expiry) {
		return g, fmt.Errorf("%w at %s", ErrGrantExpired, g.Expiry.Format(time.RFC3339))
	}
	return g, nil
}
