package derp

import (
	"context"
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

// startRelay listens on a loopback port, accepts one client, verifies its
// ClientInfo carries wantKey, then runs handler(conn) playing the relay side.
func startRelay(t *testing.T, wantKey meshproto.NodeKey, handler func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		typ, payload, err := meshproto.ReadDERPFrame(conn)
		if err != nil || typ != meshproto.DERPFrameClientInfo {
			return
		}
		var got meshproto.NodeKey
		copy(got[:], payload)
		if !got.Equal(wantKey) {
			return
		}
		handler(conn)
	}()
	return ln.Addr().String()
}

func TestClientSend(t *testing.T) {
	keyA, keyB := key(1), key(2)
	cipher := []byte("wg-encrypted")

	type sent struct {
		dst    meshproto.NodeKey
		cipher []byte
	}
	gotCh := make(chan sent, 1)
	addr := startRelay(t, keyA, func(conn net.Conn) {
		typ, payload, err := meshproto.ReadDERPFrame(conn)
		if err != nil || typ != meshproto.DERPFrameSendPacket {
			return
		}
		dst, ct, err := meshproto.SplitPacket(payload)
		if err != nil {
			return
		}
		gotCh <- sent{dst, ct}
	})

	c, err := Dial(context.Background(), addr, keyA, Auth{}, nil, slog.Default())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if err := c.Send(keyB, cipher); err != nil {
		t.Fatalf("send: %v", err)
	}

	select {
	case s := <-gotCh:
		if !s.dst.Equal(keyB) {
			t.Fatalf("dst = %s, want B", s.dst)
		}
		if string(s.cipher) != string(cipher) {
			t.Fatalf("cipher = %q, want %q", s.cipher, cipher)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay never received the SendPacket")
	}
}

func TestClientRecv(t *testing.T) {
	keyA, keyB := key(1), key(2)
	cipher := []byte("inbound-wg-bytes")

	addr := startRelay(t, keyA, func(conn net.Conn) {
		// Relay pushes a packet from B to our client.
		_ = meshproto.WriteDERPFrame(conn, meshproto.DERPFrameRecvPacket, meshproto.EncodePacket(keyB, cipher))
		time.Sleep(200 * time.Millisecond) // keep conn open long enough to deliver
	})

	type recv struct {
		src    meshproto.NodeKey
		cipher []byte
	}
	gotCh := make(chan recv, 1)
	c, err := Dial(context.Background(), addr, keyA, Auth{}, func(src meshproto.NodeKey, ct []byte) {
		gotCh <- recv{src, ct}
	}, slog.Default())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	select {
	case r := <-gotCh:
		if !r.src.Equal(keyB) {
			t.Fatalf("src = %s, want B", r.src)
		}
		if string(r.cipher) != string(cipher) {
			t.Fatalf("cipher = %q, want %q", r.cipher, cipher)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("onRecv never fired")
	}
}
