package relay

import (
	"log/slog"
	"net"
	"testing"
	"time"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

func key(b byte) meshproto.NodeKey {
	var k meshproto.NodeKey
	for i := range k {
		k[i] = b
	}
	return k
}

// connectClient wires a net.Pipe into hub.Serve and returns the caller's end
// plus the node's ClientInfo already sent.
func connectClient(t *testing.T, h *Hub, k meshproto.NodeKey) net.Conn {
	t.Helper()
	mine, theirs := net.Pipe()
	go h.Serve(theirs)
	if err := meshproto.WriteDERPFrame(mine, meshproto.DERPFrameClientInfo, k[:]); err != nil {
		t.Fatalf("send ClientInfo: %v", err)
	}
	// Wait for the hub to register (Serve reads ClientInfo then adds).
	deadline := time.Now().Add(2 * time.Second)
	for !h.Connected(k) {
		if time.Now().After(deadline) {
			t.Fatal("timeout waiting for client registration")
		}
		time.Sleep(time.Millisecond)
	}
	t.Cleanup(func() { _ = mine.Close() })
	return mine
}

func TestRelayForwardsCiphertextByKey(t *testing.T) {
	h := NewHub(slog.Default(), AuthConfig{})
	keyA, keyB := key(1), key(2)
	connA := connectClient(t, h, keyA)
	connB := connectClient(t, h, keyB)

	ciphertext := []byte("opaque-wireguard-encrypted-bytes")

	// A sends to B. Read B's side concurrently (net.Pipe write blocks on read).
	type res struct {
		typ    meshproto.DERPFrameType
		src    meshproto.NodeKey
		cipher []byte
		err    error
	}
	got := make(chan res, 1)
	go func() {
		typ, payload, err := meshproto.ReadDERPFrame(connB)
		if err != nil {
			got <- res{err: err}
			return
		}
		src, cipher, err := meshproto.SplitPacket(payload)
		got <- res{typ: typ, src: src, cipher: cipher, err: err}
	}()

	if err := meshproto.WriteDERPFrame(connA, meshproto.DERPFrameSendPacket, meshproto.EncodePacket(keyB, ciphertext)); err != nil {
		t.Fatalf("A send: %v", err)
	}

	select {
	case r := <-got:
		if r.err != nil {
			t.Fatalf("B recv: %v", r.err)
		}
		if r.typ != meshproto.DERPFrameRecvPacket {
			t.Fatalf("type = %d, want RecvPacket", r.typ)
		}
		if !r.src.Equal(keyA) {
			t.Fatalf("src = %s, want A", r.src)
		}
		if string(r.cipher) != string(ciphertext) {
			t.Fatalf("cipher = %q, want %q (relay must forward opaque bytes verbatim)", r.cipher, ciphertext)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for forwarded packet")
	}
}

func TestRelayDropsWhenDestOffline(t *testing.T) {
	h := NewHub(slog.Default(), AuthConfig{})
	keyA := key(1)
	connA := connectClient(t, h, keyA)

	// Send to a key nobody registered — must be dropped without killing A's link.
	if err := meshproto.WriteDERPFrame(connA, meshproto.DERPFrameSendPacket, meshproto.EncodePacket(key(9), []byte("x"))); err != nil {
		t.Fatalf("A send: %v", err)
	}
	// A's link should still be usable: a Ping must get a Pong back.
	if err := meshproto.WriteDERPFrame(connA, meshproto.DERPFramePing, []byte("pingpong")); err != nil {
		t.Fatalf("A ping: %v", err)
	}
	typ, payload, err := meshproto.ReadDERPFrame(connA)
	if err != nil {
		t.Fatalf("A recv pong: %v", err)
	}
	if typ != meshproto.DERPFramePong || string(payload) != "pingpong" {
		t.Fatalf("got type=%d payload=%q, want Pong/pingpong", typ, payload)
	}
}

func TestRelayRejectsNonClientInfoFirstFrame(t *testing.T) {
	h := NewHub(slog.Default(), AuthConfig{})
	mine, theirs := net.Pipe()
	done := make(chan struct{})
	go func() { h.Serve(theirs); close(done) }()

	// First frame is a SendPacket, not ClientInfo → hub must close the link.
	_ = meshproto.WriteDERPFrame(mine, meshproto.DERPFrameSendPacket, make([]byte, meshproto.KeyLen))
	// The hub closes conn; a subsequent read returns an error/EOF.
	_ = mine.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := meshproto.ReadDERPFrame(mine); err == nil {
		t.Fatal("expected the hub to close the link after a bad first frame")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after bad first frame")
	}
}
