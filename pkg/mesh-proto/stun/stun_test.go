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
		make([]byte, 4),                        // too short
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
