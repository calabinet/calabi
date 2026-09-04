package meshproto

import (
	"bytes"
	"io"
	"testing"
)

func TestDERPFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	want := []byte("wireguard-encrypted-bytes")
	if err := WriteDERPFrame(&buf, DERPFramePing, want); err != nil {
		t.Fatalf("write: %v", err)
	}
	typ, got, err := ReadDERPFrame(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if typ != DERPFramePing {
		t.Fatalf("type = %d, want %d", typ, DERPFramePing)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("payload = %q, want %q", got, want)
	}
}

func TestPacketEncodeSplit(t *testing.T) {
	var peer NodeKey
	for i := range peer {
		peer[i] = byte(i + 1)
	}
	cipher := []byte{0xde, 0xad, 0xbe, 0xef}
	frame := EncodePacket(peer, cipher)

	gotKey, gotCipher, err := SplitPacket(frame)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if !gotKey.Equal(peer) {
		t.Fatalf("key mismatch: got %s want %s", gotKey, peer)
	}
	if !bytes.Equal(gotCipher, cipher) {
		t.Fatalf("cipher = %x, want %x", gotCipher, cipher)
	}
}

func TestSplitPacketTooShort(t *testing.T) {
	if _, _, err := SplitPacket([]byte{1, 2, 3}); err != ErrShortPacket {
		t.Fatalf("err = %v, want ErrShortPacket", err)
	}
}

func TestNodeKeyTextRoundTrip(t *testing.T) {
	var k NodeKey
	for i := range k {
		k[i] = byte(255 - i)
	}
	parsed, err := ParseNodeKey(k.String())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !parsed.Equal(k) {
		t.Fatalf("round-trip mismatch: %s != %s", parsed, k)
	}
	if _, err := ParseNodeKey("not-base64!!"); err == nil {
		t.Fatal("expected error parsing invalid base64")
	}
}

func TestReadFrameTooLarge(t *testing.T) {
	// Hand-craft a header claiming a length above the cap.
	hdr := []byte{byte(DERPFrameSendPacket), 0xFF, 0xFF, 0xFF, 0xFF}
	if _, _, err := ReadDERPFrame(bytes.NewReader(hdr)); err != ErrFrameTooLarge {
		t.Fatalf("err = %v, want ErrFrameTooLarge", err)
	}
}

func TestWriteFrameTooLarge(t *testing.T) {
	if err := WriteDERPFrame(io.Discard, DERPFrameSendPacket, make([]byte, MaxDERPFrameLen+1)); err != ErrFrameTooLarge {
		t.Fatalf("err = %v, want ErrFrameTooLarge", err)
	}
}
