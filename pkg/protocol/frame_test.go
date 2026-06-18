package protocol

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// -- round-trip tests ------------------------------------------------------

func TestRoundTripEmpty(t *testing.T) {
	in := Frame{Version: CurrentMajor, Type: FramePing, RequestID: 42}
	b, err := MarshalFrame(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(b) != HeaderSize {
		t.Fatalf("len=%d want %d", len(b), HeaderSize)
	}
	out, err := UnmarshalFrame(b)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Version != in.Version || out.Type != in.Type || out.RequestID != in.RequestID {
		t.Fatalf("mismatch: in=%+v out=%+v", in, out)
	}
	if len(out.Payload) != 0 {
		t.Fatalf("expected empty payload, got %d bytes", len(out.Payload))
	}
}

func TestRoundTripWithPayload(t *testing.T) {
	payload := []byte("hello calabi, this is a sample payload of decent size " + strings.Repeat("x", 256))
	in := Frame{
		Version:   CurrentMajor,
		Type:      FrameHello,
		RequestID: 0xDEADBEEFCAFEBABE,
		Payload:   payload,
	}
	b, err := MarshalFrame(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, err := UnmarshalFrame(b)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !bytes.Equal(out.Payload, payload) {
		t.Fatalf("payload mismatch")
	}
	// Ensure output payload is independent of input buffer.
	out.Payload[0] = '!'
	if payload[0] == '!' {
		t.Fatalf("payload not copied")
	}
}

func TestStreamRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	frames := []Frame{
		{Version: 1, Type: FrameHello, RequestID: 1, Payload: []byte{1, 2, 3}},
		{Version: 1, Type: FrameHelloAck, RequestID: 1},
		{Version: 1, Type: FrameAuth, RequestID: 2, Payload: bytes.Repeat([]byte{0xAB}, 4096)},
	}
	for _, f := range frames {
		if _, err := WriteFrame(&buf, f); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	for i, want := range frames {
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if got.Type != want.Type || got.RequestID != want.RequestID || !bytes.Equal(got.Payload, want.Payload) {
			t.Fatalf("frame %d: got %+v want %+v", i, got, want)
		}
	}
	if buf.Len() != 0 {
		t.Fatalf("trailing bytes in stream: %d", buf.Len())
	}
}

// -- header validation -----------------------------------------------------

func TestBadMagic(t *testing.T) {
	b := make([]byte, HeaderSize)
	// magic = 0x0000
	if _, _, err := DecodeHeader(b); !errors.Is(err, ErrBadMagic) {
		t.Fatalf("want ErrBadMagic, got %v", err)
	}
}

func TestShortHeader(t *testing.T) {
	b := []byte{0x54, 0x58, 0x01, 0x01}
	if _, _, err := DecodeHeader(b); !errors.Is(err, ErrShortHeader) {
		t.Fatalf("want ErrShortHeader, got %v", err)
	}
}

func TestFrameTooLarge(t *testing.T) {
	in := Frame{
		Version: 1,
		Type:    FrameHello,
		Payload: make([]byte, MaxPayloadSize+1),
	}
	if _, err := MarshalFrame(in); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("want ErrFrameTooLarge on marshal, got %v", err)
	}

	// Hand-craft a header that claims an oversize length.
	hdr := make([]byte, HeaderSize)
	if err := EncodeHeader(hdr, Frame{Version: 1, Type: FrameHello}); err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Overwrite the Length field.
	hdr[4] = 0x01
	hdr[5] = 0x00
	hdr[6] = 0x00
	hdr[7] = 0x01
	if _, _, err := DecodeHeader(hdr); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("want ErrFrameTooLarge on decode, got %v", err)
	}
}

func TestShortPayload(t *testing.T) {
	in := Frame{Version: 1, Type: FrameHello, Payload: []byte{1, 2, 3, 4, 5}}
	b, err := MarshalFrame(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Truncate.
	if _, err := UnmarshalFrame(b[:HeaderSize+2]); !errors.Is(err, ErrShortPayload) {
		t.Fatalf("want ErrShortPayload, got %v", err)
	}
	// Stream read on truncated input must also fail.
	if _, err := ReadFrame(bytes.NewReader(b[:HeaderSize+2])); !errors.Is(err, ErrShortPayload) {
		t.Fatalf("want ErrShortPayload from ReadFrame, got %v", err)
	}
}

func TestReadFrameEOF(t *testing.T) {
	if _, err := ReadFrame(bytes.NewReader(nil)); !errors.Is(err, io.EOF) && !errors.Is(err, ErrShortHeader) {
		t.Fatalf("want EOF or ErrShortHeader, got %v", err)
	}
}

// -- forward-compat: unknown types are decodable ---------------------------

func TestUnknownFrameTypeRoundTrips(t *testing.T) {
	in := Frame{Version: 1, Type: FrameType(0x7A), RequestID: 99, Payload: []byte("future")}
	b, err := MarshalFrame(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, err := UnmarshalFrame(b)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Type != FrameType(0x7A) || !bytes.Equal(out.Payload, in.Payload) {
		t.Fatalf("forward-compat broken: %+v", out)
	}
	if out.Type.IsKnown() {
		t.Fatalf("0x7A should be unknown")
	}
	if out.Type.String() != "UNKNOWN" {
		t.Fatalf("unexpected string for 0x7A: %s", out.Type.String())
	}
}

// -- known type table sanity ----------------------------------------------

func TestAllKnownTypesHaveStrings(t *testing.T) {
	known := []FrameType{
		FrameHello, FrameHelloAck, FrameAuth, FrameAuthResp,
		FrameNewProxy, FrameNewProxyResp, FrameCloseProxy,
		FrameNewConn, FrameConnAck,
		FramePing, FramePong,
		FrameConfigPush, FrameMetricsReport,
		FrameGoAway, FrameError,
	}
	for _, k := range known {
		if !k.IsKnown() {
			t.Errorf("%v reports !IsKnown", k)
		}
		if k.String() == "UNKNOWN" || k.String() == "UNSPECIFIED" {
			t.Errorf("type %#x has no String()", uint8(k))
		}
	}
}

// -- fuzz: never panic on arbitrary bytes ----------------------------------

func FuzzDecodeHeader(f *testing.F) {
	// Seed with one valid header.
	hdr := make([]byte, HeaderSize)
	_ = EncodeHeader(hdr, Frame{Version: 1, Type: FrameHello, RequestID: 7})
	f.Add(hdr)
	f.Add([]byte{0x54, 0x58, 0x01, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add(make([]byte, HeaderSize))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic regardless of input.
		_, _, _ = DecodeHeader(data)
	})
}

func FuzzReadFrame(f *testing.F) {
	good, _ := MarshalFrame(Frame{Version: 1, Type: FrameHello, Payload: []byte("seed")})
	f.Add(good)
	f.Add([]byte{})
	f.Add(make([]byte, HeaderSize+1))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ReadFrame(bytes.NewReader(data))
	})
}
