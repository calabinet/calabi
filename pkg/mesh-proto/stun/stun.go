// Package stun is a minimal RFC 5389 STUN codec — just enough for
// reflexive-address discovery during mesh hole punching (MESH.4): a binding
// request, and the XOR-MAPPED-ADDRESS carried in the success response. It is NOT
// a general STUN implementation (no MESSAGE-INTEGRITY, FINGERPRINT, retransmit
// policy, or the deprecated MAPPED-ADDRESS). Shared by the client (asks a relay
// "what address do you see me at?") and calabi-derp's STUN responder. Pure and
// allocation-light so both the encode and decode paths are unit-testable.
package stun

import (
	"crypto/rand"
	"encoding/binary"
	"net/netip"
)

const (
	magicCookie      = 0x2112A442
	headerLen        = 20
	bindingRequest   = 0x0001
	bindingResponse  = 0x0101 // success
	attrXorMappedAdr = 0x0020

	famIPv4 = 0x01
	famIPv6 = 0x02
)

// TxID is a STUN transaction id — 96 bits binding a response to its request.
type TxID [12]byte

// NewTxID returns a random transaction id.
func NewTxID() (TxID, error) {
	var t TxID
	_, err := rand.Read(t[:])
	return t, err
}

// IsSTUN reports whether pkt looks like a STUN message — the magic cookie in the
// header. Used by the socket read loop to split STUN responses from DISCO / WG
// traffic on the shared UDP port.
func IsSTUN(pkt []byte) bool {
	return len(pkt) >= headerLen && binary.BigEndian.Uint32(pkt[4:8]) == magicCookie
}

// TxOf returns the transaction id in a STUN message header (call only after
// IsSTUN).
func TxOf(pkt []byte) TxID {
	var t TxID
	copy(t[:], pkt[8:20])
	return t
}

func header(msgType uint16, tx TxID, attrsLen int) []byte {
	b := make([]byte, headerLen, headerLen+attrsLen)
	binary.BigEndian.PutUint16(b[0:2], msgType)
	binary.BigEndian.PutUint16(b[2:4], uint16(attrsLen))
	binary.BigEndian.PutUint32(b[4:8], magicCookie)
	copy(b[8:20], tx[:])
	return b
}

// BindingRequest encodes a bare binding request (no attributes).
func BindingRequest(tx TxID) []byte {
	return header(bindingRequest, tx, 0)
}

// MessageType returns the message type field (bindingRequest / bindingResponse).
func messageType(pkt []byte) uint16 { return binary.BigEndian.Uint16(pkt[0:2]) }

// IsBindingRequest reports whether pkt is a STUN binding request; returns its tx.
// Used by the server.
func IsBindingRequest(pkt []byte) (TxID, bool) {
	if !IsSTUN(pkt) || messageType(pkt) != bindingRequest {
		return TxID{}, false
	}
	return TxOf(pkt), true
}

// BindingResponse encodes a binding success response reporting `from` (the source
// address the server saw) as the XOR-MAPPED-ADDRESS. The server calls this with
// the request's tx and the UDP source address.
func BindingResponse(tx TxID, from netip.AddrPort) []byte {
	attr := xorMappedAddress(tx, from)
	b := header(bindingResponse, tx, len(attr))
	return append(b, attr...)
}

// ParseBindingResponse extracts the reflexive address from a binding success
// response whose transaction id matches want. ok=false if pkt isn't a matching
// success response or has no XOR-MAPPED-ADDRESS.
func ParseBindingResponse(pkt []byte, want TxID) (netip.AddrPort, bool) {
	if !IsSTUN(pkt) || messageType(pkt) != bindingResponse || TxOf(pkt) != want {
		return netip.AddrPort{}, false
	}
	msgLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if headerLen+msgLen > len(pkt) {
		return netip.AddrPort{}, false
	}
	p := pkt[headerLen : headerLen+msgLen]
	for len(p) >= 4 {
		atype := binary.BigEndian.Uint16(p[0:2])
		alen := int(binary.BigEndian.Uint16(p[2:4]))
		if 4+alen > len(p) {
			break
		}
		val := p[4 : 4+alen]
		if atype == attrXorMappedAdr {
			if ap, ok := parseXorMappedAddress(val, TxOf(pkt)); ok {
				return ap, true
			}
		}
		// Attributes are padded to a 4-byte boundary.
		adv := 4 + alen
		if pad := adv % 4; pad != 0 {
			adv += 4 - pad
		}
		if adv > len(p) {
			break
		}
		p = p[adv:]
	}
	return netip.AddrPort{}, false
}

// xorMappedAddress encodes an XOR-MAPPED-ADDRESS attribute (type + length +
// value) for ap.
func xorMappedAddress(tx TxID, ap netip.AddrPort) []byte {
	addr := ap.Addr().Unmap()
	xport := ap.Port() ^ (magicCookie >> 16)

	var val []byte
	if addr.Is4() {
		ip := addr.As4()
		var cookie [4]byte
		binary.BigEndian.PutUint32(cookie[:], magicCookie)
		val = make([]byte, 8)
		val[1] = famIPv4
		binary.BigEndian.PutUint16(val[2:4], xport)
		for i := 0; i < 4; i++ {
			val[4+i] = ip[i] ^ cookie[i]
		}
	} else {
		ip := addr.As16()
		var mask [16]byte
		binary.BigEndian.PutUint32(mask[0:4], magicCookie)
		copy(mask[4:16], tx[:])
		val = make([]byte, 20)
		val[1] = famIPv6
		binary.BigEndian.PutUint16(val[2:4], xport)
		for i := 0; i < 16; i++ {
			val[4+i] = ip[i] ^ mask[i]
		}
	}
	attr := make([]byte, 4, 4+len(val))
	binary.BigEndian.PutUint16(attr[0:2], attrXorMappedAdr)
	binary.BigEndian.PutUint16(attr[2:4], uint16(len(val)))
	return append(attr, val...)
}

func parseXorMappedAddress(val []byte, tx TxID) (netip.AddrPort, bool) {
	if len(val) < 8 {
		return netip.AddrPort{}, false
	}
	fam := val[1]
	port := binary.BigEndian.Uint16(val[2:4]) ^ (magicCookie >> 16)
	switch fam {
	case famIPv4:
		if len(val) < 8 {
			return netip.AddrPort{}, false
		}
		var cookie [4]byte
		binary.BigEndian.PutUint32(cookie[:], magicCookie)
		var ip [4]byte
		for i := 0; i < 4; i++ {
			ip[i] = val[4+i] ^ cookie[i]
		}
		return netip.AddrPortFrom(netip.AddrFrom4(ip), port), true
	case famIPv6:
		if len(val) < 20 {
			return netip.AddrPort{}, false
		}
		var mask [16]byte
		binary.BigEndian.PutUint32(mask[0:4], magicCookie)
		copy(mask[4:16], tx[:])
		var ip [16]byte
		for i := 0; i < 16; i++ {
			ip[i] = val[4+i] ^ mask[i]
		}
		return netip.AddrPortFrom(netip.AddrFrom16(ip), port), true
	default:
		return netip.AddrPort{}, false
	}
}
