package mesh

import (
	"crypto/rand"
	"encoding/binary"
	"net/netip"

	"golang.org/x/crypto/nacl/box"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// DISCO is the peer-to-peer NAT-traversal protocol (MESH.4): short ping/pong
// probes a node sends over its direct-path UDP socket to find out which of a
// peer's candidate endpoints actually reach it. It is SEPARATE from WireGuard —
// it authenticates with the node's disco key (not the traffic key), so path
// discovery can't be used to forge or read data-plane traffic.
//
// Wire layout of a DISCO datagram (so the shared socket's read loop can tell it
// apart from STUN and WireGuard):
//
//	[6]  discoMagic
//	[32] sender disco public key   (lets the receiver pick the box key)
//	[24] nonce
//	[.] NaCl box(plaintext) sealed to (sender disco priv, receiver disco pub)
//
// The sealed plaintext is a discoMessage. The box gives confidentiality + sender
// authentication + tamper detection in one step.
var discoMagic = [6]byte{'c', 'a', 'l', 'a', 'D', '1'}

const (
	discoNonceLen  = 24
	discoHeaderLen = 6 + meshproto.KeyLen + discoNonceLen // magic + sender pub + nonce
)

type discoMsgType byte

const (
	discoPing discoMsgType = 1
	discoPong discoMsgType = 2
)

// discoTxID ties a pong to its ping.
type discoTxID [12]byte

func newDiscoTxID() (discoTxID, error) {
	var t discoTxID
	_, err := rand.Read(t[:])
	return t, err
}

// discoMessage is a DISCO ping or pong. Src is set only on a pong: the address
// the ponger saw the ping arrive from, so the pinger learns which candidate
// endpoint reached the peer (and its per-peer reflexive address).
type discoMessage struct {
	Type discoMsgType
	Tx   discoTxID
	Src  netip.AddrPort
}

func encodeDiscoMessage(m discoMessage) []byte {
	b := make([]byte, 0, 1+12+19)
	b = append(b, byte(m.Type))
	b = append(b, m.Tx[:]...)
	if m.Type == discoPong && m.Src.IsValid() {
		a := m.Src.Addr()
		if a.Is4() {
			ip := a.As4()
			b = append(b, 4)
			b = append(b, ip[:]...)
		} else {
			ip := a.As16()
			b = append(b, 16)
			b = append(b, ip[:]...)
		}
		var port [2]byte
		binary.BigEndian.PutUint16(port[:], m.Src.Port())
		b = append(b, port[:]...)
	}
	return b
}

func decodeDiscoMessage(b []byte) (discoMessage, bool) {
	if len(b) < 13 {
		return discoMessage{}, false
	}
	m := discoMessage{Type: discoMsgType(b[0])}
	copy(m.Tx[:], b[1:13])
	switch m.Type {
	case discoPing:
		return m, true
	case discoPong:
		rest := b[13:]
		if len(rest) == 0 {
			return m, true // a pong may omit the observed source
		}
		fam := rest[0]
		rest = rest[1:]
		var ipLen int
		switch fam {
		case 4:
			ipLen = 4
		case 16:
			ipLen = 16
		default:
			return discoMessage{}, false
		}
		if len(rest) < ipLen+2 {
			return discoMessage{}, false
		}
		var a netip.Addr
		if ipLen == 4 {
			var ip [4]byte
			copy(ip[:], rest[:4])
			a = netip.AddrFrom4(ip)
		} else {
			var ip [16]byte
			copy(ip[:], rest[:16])
			a = netip.AddrFrom16(ip)
		}
		port := binary.BigEndian.Uint16(rest[ipLen : ipLen+2])
		m.Src = netip.AddrPortFrom(a, port)
		return m, true
	default:
		return discoMessage{}, false
	}
}

// isDisco reports whether pkt is a DISCO datagram (magic prefix + minimum
// length) — the read-loop demux uses it after ruling out STUN.
func isDisco(pkt []byte) bool {
	if len(pkt) < discoHeaderLen {
		return false
	}
	for i := range discoMagic {
		if pkt[i] != discoMagic[i] {
			return false
		}
	}
	return true
}

// sealDisco encodes and seals a DISCO message to peerPub. The result is a
// complete datagram ready to send over the direct-path socket.
func sealDisco(myPriv DiscoPrivateKey, peerPub meshproto.DiscoKey, m discoMessage) ([]byte, error) {
	var nonce [discoNonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	myPub := myPriv.Public()
	out := make([]byte, 0, discoHeaderLen+48)
	out = append(out, discoMagic[:]...)
	out = append(out, myPub[:]...)
	out = append(out, nonce[:]...)

	priv := [32]byte(myPriv)
	pub := [32]byte(peerPub)
	out = box.Seal(out, encodeDiscoMessage(m), &nonce, &pub, &priv)
	return out, nil
}

// openDisco verifies + decrypts a DISCO datagram addressed to us, returning the
// sender's disco public key and the message. ok=false for a non-DISCO packet, a
// box that fails authentication (wrong sender/recipient or tampered), or a
// malformed plaintext.
func openDisco(myPriv DiscoPrivateKey, pkt []byte) (meshproto.DiscoKey, discoMessage, bool) {
	if !isDisco(pkt) {
		return meshproto.DiscoKey{}, discoMessage{}, false
	}
	var sender meshproto.DiscoKey
	copy(sender[:], pkt[6:6+meshproto.KeyLen])
	var nonce [discoNonceLen]byte
	copy(nonce[:], pkt[6+meshproto.KeyLen:discoHeaderLen])

	priv := [32]byte(myPriv)
	pub := [32]byte(sender)
	plain, ok := box.Open(nil, pkt[discoHeaderLen:], &nonce, &pub, &priv)
	if !ok {
		return meshproto.DiscoKey{}, discoMessage{}, false
	}
	m, ok := decodeDiscoMessage(plain)
	if !ok {
		return meshproto.DiscoKey{}, discoMessage{}, false
	}
	return sender, m, true
}
