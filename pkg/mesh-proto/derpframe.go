package meshproto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// DERP wire frame (node<->relay). v0 draft — mirrors the length-prefixed TLV
// style of pkg/protocol. A DERP relay forwards ONLY these frames and never sees
// plaintext: the Payload of a packet frame is already WireGuard-encrypted by the
// sending node, so a relay can route by public key but cannot read traffic.
//
// Frame layout on the wire:
//
//	+--------+------------------+-------------------------+
//	| type   | length (uint32)  | payload (length bytes)  |
//	| 1 byte | 4 bytes, big-end |                         |
//	+--------+------------------+-------------------------+
//
// For the packet frames the payload is itself structured as a 32-byte peer key
// followed by the opaque ciphertext (see EncodeSendPacket / SplitPacket).

// DERPFrameType tags a DERP frame.
type DERPFrameType uint8

const (
	// DERPFrameInvalid is the zero value; never sent.
	DERPFrameInvalid DERPFrameType = iota
	// DERPFrameClientInfo is the first frame a node sends after connecting:
	// payload = its NodeKey (32 bytes). Tells the relay who is on this link.
	DERPFrameClientInfo
	// DERPFrameSendPacket is node->relay: payload = dst NodeKey (32B) || ciphertext.
	DERPFrameSendPacket
	// DERPFrameRecvPacket is relay->node: payload = src NodeKey (32B) || ciphertext.
	DERPFrameRecvPacket
	// DERPFramePing / DERPFramePong keep the link alive and measure RTT: payload
	// = 8 opaque bytes echoed back.
	DERPFramePing
	DERPFramePong
	// DERPFrameAuthChallenge is relay->node: payload = ephemeral public key (32B)
	// || nonce (24B). Sent right after ClientInfo, and again whenever the relay
	// wants the node to re-prove itself (a lapsing grant). See derpauth.go.
	DERPFrameAuthChallenge
	// DERPFrameAuthProof is node->relay, answering a challenge: payload =
	// grant length (2B) || grant || sealed proof. See derpauth.go.
	DERPFrameAuthProof
)

// MaxDERPFrameLen caps a single frame's payload so a malformed length can't make
// a peer allocate unbounded memory. 64 KiB comfortably fits a WG packet + key.
const MaxDERPFrameLen = 64 * 1024

var (
	// ErrFrameTooLarge is returned when a frame's declared length exceeds MaxDERPFrameLen.
	ErrFrameTooLarge = errors.New("meshproto: DERP frame exceeds max length")
	// ErrShortPacket is returned when a packet frame is too short to hold a peer key.
	ErrShortPacket = errors.New("meshproto: packet frame shorter than key length")
)

// WriteDERPFrame encodes one frame to w.
func WriteDERPFrame(w io.Writer, t DERPFrameType, payload []byte) error {
	if len(payload) > MaxDERPFrameLen {
		return ErrFrameTooLarge
	}
	var hdr [5]byte
	hdr[0] = byte(t)
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("meshproto: write frame header: %w", err)
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return fmt.Errorf("meshproto: write frame payload: %w", err)
		}
	}
	return nil
}

// ReadDERPFrame reads one frame from r. The returned payload is a fresh slice
// owned by the caller.
func ReadDERPFrame(r io.Reader) (DERPFrameType, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return DERPFrameInvalid, nil, err // io.EOF / ErrUnexpectedEOF pass through
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > MaxDERPFrameLen {
		return DERPFrameInvalid, nil, ErrFrameTooLarge
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return DERPFrameInvalid, nil, fmt.Errorf("meshproto: read frame payload: %w", err)
	}
	return DERPFrameType(hdr[0]), payload, nil
}

// EncodePacket builds a packet-frame payload: peerKey || ciphertext. Used for
// both Send (dst key) and Recv (src key) frames.
func EncodePacket(peer NodeKey, ciphertext []byte) []byte {
	out := make([]byte, KeyLen+len(ciphertext))
	copy(out, peer[:])
	copy(out[KeyLen:], ciphertext)
	return out
}

// SplitPacket parses a packet-frame payload back into (peerKey, ciphertext).
// The returned ciphertext aliases payload; copy it if you need to retain it.
func SplitPacket(payload []byte) (NodeKey, []byte, error) {
	var k NodeKey
	if len(payload) < KeyLen {
		return k, nil, ErrShortPacket
	}
	copy(k[:], payload[:KeyLen])
	return k, payload[KeyLen:], nil
}
