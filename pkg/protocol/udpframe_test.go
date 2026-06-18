package protocol

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// Round-trip a small payload through Write+Read.
func TestUDPDatagram_RoundTrip(t *testing.T) {
	var buf bytes.Buffer
	for _, msg := range [][]byte{
		[]byte("hello"),
		make([]byte, 0),             // 0-length keep-alive
		bytes.Repeat([]byte("x"), 1024),
		bytes.Repeat([]byte("Y"), MaxUDPDatagram),
	} {
		if err := WriteUDPDatagram(&buf, msg); err != nil {
			t.Fatalf("write %d bytes: %v", len(msg), err)
		}
	}
	// Reads come back in the same order.
	want := []int{5, 0, 1024, MaxUDPDatagram}
	for i, w := range want {
		got, err := ReadUDPDatagram(&buf)
		if err != nil {
			t.Fatalf("read[%d]: %v", i, err)
		}
		if len(got) != w {
			t.Fatalf("read[%d]: want len=%d got=%d", i, w, len(got))
		}
	}
}

// Oversize datagram is rejected without writing anything to the stream.
func TestWriteUDPDatagram_OversizeRejected(t *testing.T) {
	var buf bytes.Buffer
	too := make([]byte, MaxUDPDatagram+1)
	if err := WriteUDPDatagram(&buf, too); err == nil {
		t.Fatalf("expected error on oversize datagram")
	}
	if buf.Len() != 0 {
		t.Fatalf("oversize write should not leak bytes, buf=%d", buf.Len())
	}
}

// Mid-frame truncation surfaces as ErrUDPFrameTruncated (NOT io.EOF) so
// the conntrack reaper can distinguish "visitor went away" from "stream
// is corrupt and we should hard-close".
func TestReadUDPDatagram_TruncatedPayload(t *testing.T) {
	var buf bytes.Buffer
	// claim 100 bytes, deliver only 5
	buf.Write([]byte{0x00, 0x64}) // len=100
	buf.WriteString("hello")
	_, err := ReadUDPDatagram(&buf)
	if !errors.Is(err, ErrUDPFrameTruncated) {
		t.Fatalf("expected ErrUDPFrameTruncated, got %v", err)
	}
}

// Clean EOF between frames is a clean io.EOF, not truncation.
func TestReadUDPDatagram_CleanEOF(t *testing.T) {
	_, err := ReadUDPDatagram(&bytes.Buffer{})
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF on empty buffer, got %v", err)
	}
}
