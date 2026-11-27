package stun

import (
	"net/netip"
	"testing"
)

// A binding request the server turns into a response must round-trip the source
// address the client parses back out — for both v4 and v6.
func TestBindingRoundTrip(t *testing.T) {
	for _, want := range []netip.AddrPort{
		netip.MustParseAddrPort("203.0.113.7:51820"),
		netip.MustParseAddrPort("[2001:db8::abcd]:41641"),
		netip.MustParseAddrPort("192.168.1.2:1"),
		netip.MustParseAddrPort("8.8.8.8:65535"),
	} {
		tx, err := NewTxID()
		if err != nil {
			t.Fatal(err)
		}
		req := BindingRequest(tx)
		if !IsSTUN(req) {
			t.Fatalf("%s: request not recognized as STUN", want)
		}
		gotTx, ok := IsBindingRequest(req)
		if !ok || gotTx != tx {
			t.Fatalf("%s: server did not see a binding request with tx", want)
		}

		resp := BindingResponse(gotTx, want)
		if !IsSTUN(resp) {
			t.Fatalf("%s: response not STUN", want)
		}
		got, ok := ParseBindingResponse(resp, tx)
		if !ok {
			t.Fatalf("%s: response did not parse", want)
		}
		if got != want {
			t.Fatalf("reflexive addr round-trip: got %s, want %s", got, want)
		}
	}
}

// A response whose transaction id doesn't match is rejected (it belongs to a
// different in-flight request).
func TestParseBindingResponseWrongTx(t *testing.T) {
	tx, _ := NewTxID()
	other, _ := NewTxID()
	resp := BindingResponse(tx, netip.MustParseAddrPort("203.0.113.9:1234"))
	if _, ok := ParseBindingResponse(resp, other); ok {
		t.Fatal("response with a mismatched tx must not parse")
	}
}

func TestIsSTUNRejectsGarbage(t *testing.T) {
	for _, b := range [][]byte{
		nil,
		make([]byte, 4), // too short
		append([]byte{0, 1, 0, 0}, make([]byte, 16)...), // no magic cookie
	} {
		if IsSTUN(b) {
			t.Fatalf("garbage %v accepted as STUN", b)
		}
	}
	// A non-request STUN message is STUN but not a binding request.
	resp := BindingResponse(TxID{}, netip.MustParseAddrPort("1.2.3.4:5"))
	if _, ok := IsBindingRequest(resp); ok {
		t.Fatal("a binding response must not read as a binding request")
	}
}

func TestRFC5780ChangeRequestAndOtherAddress(t *testing.T) {
	for _, tc := range []struct {
		changeIP, changePort bool
	}{
		{false, false},
		{false, true},
		{true, false},
		{true, true},
	} {
		tx, err := NewTxID()
		if err != nil {
			t.Fatal(err)
		}
		req := BindingRequestChange(tx, tc.changeIP, tc.changePort)
		gotTx, gotIP, gotPort, ok := ParseChangeRequest(req)
		if !ok || gotTx != tx || gotIP != tc.changeIP || gotPort != tc.changePort {
			t.Fatalf("ParseChangeRequest(%v,%v) = (%v,%v,%v,%v)", tc.changeIP, tc.changePort, gotTx, gotIP, gotPort, ok)
		}
	}

	tx, err := NewTxID()
	if err != nil {
		t.Fatal(err)
	}
	mapped := netip.MustParseAddrPort("203.0.113.10:54321")
	other := netip.MustParseAddrPort("198.51.100.2:3479")
	resp := BindingResponseWithOther(tx, mapped, other)
	detail, ok := ParseBindingResponseDetail(resp, tx)
	if !ok {
		t.Fatal("ParseBindingResponseDetail failed")
	}
	if detail.Mapped != mapped || detail.Other != other {
		t.Fatalf("got mapped=%s other=%s, want %s / %s", detail.Mapped, detail.Other, mapped, other)
	}
}

func TestParseBindingResponseLegacyFallback(t *testing.T) {
	tx, _ := NewTxID()
	mapped := netip.MustParseAddrPort("203.0.113.20:41234")
	changed := netip.MustParseAddrPort("198.51.100.9:3479")
	// Build a legacy RFC 3489 response carrying MAPPED-ADDRESS + CHANGED-ADDRESS.
	mv := encodePlainAddr(mapped)
	cv := encodePlainAddr(changed)
	msgLen := 4 + len(mv) + 4 + len(cv)
	pkt := make([]byte, headerLen+msgLen)
	pkt[0], pkt[1] = 0x01, 0x01
	pkt[2], pkt[3] = byte(msgLen>>8), byte(msgLen)
	pkt[4], pkt[5], pkt[6], pkt[7] = 0x21, 0x12, 0xa4, 0x42
	copy(pkt[8:20], tx[:])
	off := headerLen
	pkt[off], pkt[off+1] = 0x00, 0x01 // MAPPED-ADDRESS
	pkt[off+2], pkt[off+3] = 0x00, byte(len(mv))
	copy(pkt[off+4:], mv)
	off += 4 + len(mv)
	pkt[off], pkt[off+1] = 0x00, 0x05 // CHANGED-ADDRESS
	pkt[off+2], pkt[off+3] = 0x00, byte(len(cv))
	copy(pkt[off+4:], cv)

	detail, ok := ParseBindingResponseDetail(pkt, tx)
	if !ok {
		t.Fatal("legacy response did not parse")
	}
	if detail.Mapped != mapped || detail.Other != changed {
		t.Fatalf("got mapped=%s other=%s, want %s / %s", detail.Mapped, detail.Other, mapped, changed)
	}
}
