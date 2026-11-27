// Package stun is a minimal RFC 5389 STUN codec — just enough for
// reflexive-address discovery during mesh hole punching: a binding
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
	magicCookie       = 0x2112A442
	headerLen         = 20
	bindingRequest    = 0x0001
	bindingResponse   = 0x0101 // success
	attrMappedAdr     = 0x0001
	attrChangeRequest = 0x0003
	attrChangedAdr    = 0x0005
	attrXorMappedAdr  = 0x0020
	attrOtherAdr      = 0x802c

	changeIPFlag   uint32 = 0x04
	changePortFlag uint32 = 0x02

	famIPv4 = 0x01
	famIPv6 = 0x02
)

// BindingDetail holds the addresses parsed from a STUN Binding Response.
// Mapped is XOR-MAPPED-ADDRESS (falling back to legacy MAPPED-ADDRESS).
// Other is OTHER-ADDRESS (falling back to legacy CHANGED-ADDRESS) when the
// server advertises an alternate IP/port for RFC 5780 NAT behavior discovery.
type BindingDetail struct {
	Mapped netip.AddrPort
	Other  netip.AddrPort
}

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

// BindingRequestChange encodes an RFC 5780 Binding Request carrying a
// CHANGE-REQUEST attribute asking the STUN server to reply from a different IP
// and/or port.
func BindingRequestChange(tx TxID, changeIP, changePort bool) []byte {
	var flags uint32
	if changeIP {
		flags |= changeIPFlag
	}
	if changePort {
		flags |= changePortFlag
	}
	b := header(bindingRequest, tx, 8)
	attr := make([]byte, 8)
	binary.BigEndian.PutUint16(attr[0:2], attrChangeRequest)
	binary.BigEndian.PutUint16(attr[2:4], 4)
	binary.BigEndian.PutUint32(attr[4:8], flags)
	return append(b, attr...)
}

// ParseChangeRequest inspects a Binding Request and reports its transaction ID
// plus any RFC 5780 CHANGE-REQUEST flags.
func ParseChangeRequest(pkt []byte) (tx TxID, changeIP, changePort, ok bool) {
	tx, ok = IsBindingRequest(pkt)
	if !ok {
		return TxID{}, false, false, false
	}
	msgLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if headerLen+msgLen > len(pkt) {
		return TxID{}, false, false, false
	}
	p := pkt[headerLen : headerLen+msgLen]
	for len(p) >= 4 {
		atype := binary.BigEndian.Uint16(p[0:2])
		alen := int(binary.BigEndian.Uint16(p[2:4]))
		if 4+alen > len(p) {
			break
		}
		if atype == attrChangeRequest && alen == 4 {
			flags := binary.BigEndian.Uint32(p[4:8])
			changeIP = flags&changeIPFlag != 0
			changePort = flags&changePortFlag != 0
		}
		adv := 4 + alen
		if pad := adv % 4; pad != 0 {
			adv += 4 - pad
		}
		if adv > len(p) {
			break
		}
		p = p[adv:]
	}
	return tx, changeIP, changePort, true
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
	return BindingResponseWithOther(tx, from, netip.AddrPort{})
}

// BindingResponseWithOther encodes a Binding Success Response carrying
// XOR-MAPPED-ADDRESS and, when other is valid, an RFC 5780 OTHER-ADDRESS
// attribute.
func BindingResponseWithOther(tx TxID, from, other netip.AddrPort) []byte {
	attr := xorMappedAddress(tx, from)
	var otherAttr []byte
	if other.IsValid() {
		otherAttr = plainAddressAttr(attrOtherAdr, other)
	}
	b := header(bindingResponse, tx, len(attr)+len(otherAttr))
	b = append(b, attr...)
	return append(b, otherAttr...)
}

// ParseBindingResponse extracts the reflexive address from a binding success
// response whose transaction id matches want. ok=false if pkt isn't a matching
// success response or has no mapped address.
func ParseBindingResponse(pkt []byte, want TxID) (netip.AddrPort, bool) {
	d, ok := ParseBindingResponseDetail(pkt, want)
	if !ok {
		return netip.AddrPort{}, false
	}
	return d.Mapped, true
}

// ParseBindingResponseDetail extracts the mapped address (XOR-MAPPED-ADDRESS,
// falling back to legacy MAPPED-ADDRESS) and optional alternate server address
// (OTHER-ADDRESS, falling back to CHANGED-ADDRESS) from a binding response.
func ParseBindingResponseDetail(pkt []byte, want TxID) (BindingDetail, bool) {
	if !IsSTUN(pkt) || messageType(pkt) != bindingResponse || TxOf(pkt) != want {
		return BindingDetail{}, false
	}
	msgLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if headerLen+msgLen > len(pkt) {
		return BindingDetail{}, false
	}
	var detail BindingDetail
	var hasXorMapped, hasOther bool
	p := pkt[headerLen : headerLen+msgLen]
	for len(p) >= 4 {
		atype := binary.BigEndian.Uint16(p[0:2])
		alen := int(binary.BigEndian.Uint16(p[2:4]))
		if 4+alen > len(p) {
			break
		}
		val := p[4 : 4+alen]
		switch atype {
		case attrXorMappedAdr:
			if ap, ok := parseXorMappedAddress(val, TxOf(pkt)); ok {
				detail.Mapped = ap
				hasXorMapped = true
			}
		case attrMappedAdr:
			if !hasXorMapped {
				if ap, ok := parsePlainAddress(val); ok {
					detail.Mapped = ap
				}
			}
		case attrOtherAdr:
			if ap, ok := parsePlainAddress(val); ok {
				detail.Other = ap
				hasOther = true
			}
		case attrChangedAdr:
			if !hasOther {
				if ap, ok := parsePlainAddress(val); ok {
					detail.Other = ap
				}
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
	if !detail.Mapped.IsValid() {
		return BindingDetail{}, false
	}
	return detail, true
}

func encodePlainAddr(ap netip.AddrPort) []byte {
	addr := ap.Addr().Unmap()
	port := ap.Port()
	if addr.Is4() {
		ip := addr.As4()
		val := make([]byte, 8)
		val[1] = famIPv4
		binary.BigEndian.PutUint16(val[2:4], port)
		copy(val[4:8], ip[:])
		return val
	}
	ip := addr.As16()
	val := make([]byte, 20)
	val[1] = famIPv6
	binary.BigEndian.PutUint16(val[2:4], port)
	copy(val[4:20], ip[:])
	return val
}

func plainAddressAttr(atype uint16, ap netip.AddrPort) []byte {
	val := encodePlainAddr(ap)
	attr := make([]byte, 4, 4+len(val))
	binary.BigEndian.PutUint16(attr[0:2], atype)
	binary.BigEndian.PutUint16(attr[2:4], uint16(len(val)))
	return append(attr, val...)
}

func parsePlainAddress(val []byte) (netip.AddrPort, bool) {
	if len(val) < 8 {
		return netip.AddrPort{}, false
	}
	fam := val[1]
	port := binary.BigEndian.Uint16(val[2:4])
	switch fam {
	case famIPv4:
		var ip [4]byte
		copy(ip[:], val[4:8])
		return netip.AddrPortFrom(netip.AddrFrom4(ip), port), true
	case famIPv6:
		if len(val) < 20 {
			return netip.AddrPort{}, false
		}
		var ip [16]byte
		copy(ip[:], val[4:20])
		return netip.AddrPortFrom(netip.AddrFrom16(ip), port), true
	default:
		return netip.AddrPort{}, false
	}
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
