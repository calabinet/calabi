package protocol

import (
	"errors"
	"reflect"
	"testing"
)

func TestPayloadRoundTrip(t *testing.T) {
	in := &HelloRequest{
		ProtocolMajor: 1,
		ClientVersion: "calabi/0.1.0",
		OS:            "linux",
		Arch:          "amd64",
		Ts:            1716240000000,
		Nonce:         []byte("0123456789abcdef"),
		Features:      []string{"udp", "0rtt"},
	}
	b, err := Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out HelloRequest
	if err := Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(in, &out) {
		t.Fatalf("mismatch:\nin=%+v\nout=%+v", in, out)
	}
}

func TestEncodePayloadProducesValidFrame(t *testing.T) {
	frm, err := EncodePayload(FramePing, &Ping{ClientSendNs: 12345})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if frm.Type != FramePing {
		t.Fatalf("type=%v", frm.Type)
	}
	if frm.Version != CurrentMajor {
		t.Fatalf("version=%d", frm.Version)
	}
	// Round-trip through MarshalFrame/UnmarshalFrame.
	raw, err := MarshalFrame(frm)
	if err != nil {
		t.Fatalf("marshal frame: %v", err)
	}
	out, err := UnmarshalFrame(raw)
	if err != nil {
		t.Fatalf("unmarshal frame: %v", err)
	}
	var ping Ping
	if err := Unmarshal(out.Payload, &ping); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if ping.ClientSendNs != 12345 {
		t.Fatalf("got %d", ping.ClientSendNs)
	}
}

func TestEmptyPayloadUnmarshalNoop(t *testing.T) {
	var got HelloRequest
	if err := Unmarshal(nil, &got); err != nil {
		t.Fatalf("nil: %v", err)
	}
	if err := Unmarshal([]byte{}, &got); err != nil {
		t.Fatalf("empty: %v", err)
	}
}

func TestErrorPayloadImplementsError(t *testing.T) {
	e := NewError(CodeProxyDuplicate, "calabi.err.proxy.duplicate", "domain already taken")
	var ie error = e
	if ie.Error() == "" {
		t.Fatalf("empty error string")
	}
	// Identity check via errors.As.
	var target *ErrorPayload
	if !errors.As(ie, &target) {
		t.Fatalf("errors.As failed")
	}
	if target.Code != CodeProxyDuplicate {
		t.Fatalf("code lost")
	}
}
