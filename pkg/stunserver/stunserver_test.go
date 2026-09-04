package stunserver

import (
	"net"
	"testing"
	"time"

	"github.com/calabi/calabi/pkg/mesh-proto/stun"
)

// A real client socket asking a real server socket for its reflexive address must
// get back the source address the server observed — i.e. the client's own local
// address on the loopback exchange.
func TestServeAnswersBindingRequest(t *testing.T) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go Serve(srv, nil)

	cli, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	tx, _ := stun.NewTxID()
	if _, err := cli.WriteToUDP(stun.BindingRequest(tx), srv.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}

	_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := cli.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	got, ok := stun.ParseBindingResponse(buf[:n], tx)
	if !ok {
		t.Fatal("response did not parse")
	}
	// The server should have observed our client socket's local address.
	want := cli.LocalAddr().(*net.UDPAddr)
	if got.Port() != uint16(want.Port) || got.Addr().String() != "127.0.0.1" {
		t.Fatalf("reflexive = %s, want 127.0.0.1:%d", got, want.Port)
	}
}

// A non-STUN datagram is ignored (no response, no crash).
func TestServeIgnoresNonSTUN(t *testing.T) {
	srv, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	defer srv.Close()
	go Serve(srv, nil)

	cli, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	defer cli.Close()
	_, _ = cli.WriteToUDP([]byte("not stun"), srv.LocalAddr().(*net.UDPAddr))

	_ = cli.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 1500)
	if _, _, err := cli.ReadFromUDP(buf); err == nil {
		t.Fatal("expected no response to a non-STUN datagram")
	}
}
