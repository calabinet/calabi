package mesh

import (
	"net/netip"
	"testing"

	"github.com/calabi/calabi/pkg/mesh-proto/stun"
)

func TestDiscoSealOpenRoundTrip(t *testing.T) {
	a, _ := GenerateDiscoKey() // pinger
	b, _ := GenerateDiscoKey() // ponger

	tx, err := newDiscoTxID()
	if err != nil {
		t.Fatal(err)
	}
	cases := []discoMessage{
		{Type: discoPing, Tx: tx},
		{Type: discoPong, Tx: tx, Src: netip.MustParseAddrPort("203.0.113.7:41641")},
		{Type: discoPong, Tx: tx, Src: netip.MustParseAddrPort("[2001:db8::5]:51820")},
		{Type: discoPong, Tx: tx}, // pong without an observed source
	}
	for _, m := range cases {
		// a -> b
		pkt, err := sealDisco(a, b.Public(), m)
		if err != nil {
			t.Fatalf("seal %v: %v", m.Type, err)
		}
		if !isDisco(pkt) {
			t.Fatalf("%v: sealed packet not recognized as DISCO", m.Type)
		}
		sender, got, ok := openDisco(b, pkt)
		if !ok {
			t.Fatalf("%v: open failed", m.Type)
		}
		if sender != a.Public() {
			t.Fatalf("%v: sender = %s, want %s", m.Type, sender, a.Public())
		}
		if got.Type != m.Type || got.Tx != m.Tx || got.Src != m.Src {
			t.Fatalf("%v: round-trip mismatch got %+v want %+v", m.Type, got, m)
		}
	}
}

// A datagram sealed to peer b must not open for a third party c (box
// authentication binds it to the intended recipient).
func TestDiscoWrongRecipient(t *testing.T) {
	a, _ := GenerateDiscoKey()
	b, _ := GenerateDiscoKey()
	c, _ := GenerateDiscoKey()
	tx, _ := newDiscoTxID()
	pkt, _ := sealDisco(a, b.Public(), discoMessage{Type: discoPing, Tx: tx})
	if _, _, ok := openDisco(c, pkt); ok {
		t.Fatal("a packet sealed to b must not open for c")
	}
}

// Any tamper past the header fails the box's authentication.
func TestDiscoTamperDetected(t *testing.T) {
	a, _ := GenerateDiscoKey()
	b, _ := GenerateDiscoKey()
	tx, _ := newDiscoTxID()
	pkt, _ := sealDisco(a, b.Public(), discoMessage{Type: discoPing, Tx: tx})
	pkt[len(pkt)-1] ^= 0x01 // flip a ciphertext bit
	if _, _, ok := openDisco(b, pkt); ok {
		t.Fatal("tampered DISCO packet must not open")
	}
}

func TestIsDiscoRejectsOthers(t *testing.T) {
	if isDisco(nil) || isDisco(make([]byte, discoHeaderLen-1)) {
		t.Fatal("short buffers must not read as DISCO")
	}
	// A STUN datagram must not be mistaken for DISCO (the read loop checks STUN
	// first, but the magics must be disjoint regardless).
	tx, _ := stun.NewTxID()
	if isDisco(stun.BindingRequest(tx)) {
		t.Fatal("a STUN datagram must not read as DISCO")
	}
	if stun.IsSTUN(func() []byte {
		a, _ := GenerateDiscoKey()
		b, _ := GenerateDiscoKey()
		dtx, _ := newDiscoTxID()
		p, _ := sealDisco(a, b.Public(), discoMessage{Type: discoPing, Tx: dtx})
		return p
	}()) {
		t.Fatal("a DISCO datagram must not read as STUN")
	}
}
