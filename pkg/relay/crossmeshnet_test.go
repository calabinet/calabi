package relay

// SECURITY AUDIT 1-D - a relay running with authentication must not forward
// between meshnets. Before the fix the hub forwarded any SendPacket to any
// connected key: WireGuard on the far side drops it, but the relay has already
// delivered it by then, and relay usage is billed as the RECEIVER egress - so a
// node of another org could run up your bill with junk addressed to your key.
//
//   go test./pkg/relay/ -run TestRelayRefusesCrossMeshnet -v

import (
	"log/slog"
	"net"
	"testing"
	"time"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

func (c coord) grantIn(t *testing.T, node meshproto.NodeKey, meshnet int64) []byte {
	t.Helper()
	b, err := meshproto.SignRelayGrant(c.priv, meshproto.RelayGrant{
		Node: node, Meshnet: meshnet, Scope: meshproto.RelayScopeAll, Expiry: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("sign grant: %v", err)
	}
	return b
}

// joinMeshnet connects a freshly keyed node that proves a grant for meshnet.
func joinMeshnet(t *testing.T, h *Hub, c coord, meshnet int64) (meshproto.NodeKey, net.Conn) {
	t.Helper()
	nk, priv := nodeKeys(t)
	mine, theirs := net.Pipe()
	t.Cleanup(func() { _ = mine.Close() })
	go h.Serve(theirs)
	if err := handshake(t, mine, nk, priv, c.grantIn(t, nk, meshnet)); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	eventually(t, connected(h, nk, true), "node never registered")
	return nk, mine
}

// firstRelayed reads until a RecvPacket arrives or the window closes.
func firstRelayed(conn net.Conn, within time.Duration) (meshproto.NodeKey, bool) {
	deadline := time.Now().Add(within)
	for {
		_ = conn.SetReadDeadline(deadline)
		typ, payload, err := meshproto.ReadDERPFrame(conn)
		if err != nil {
			return meshproto.NodeKey{}, false
		}
		if typ != meshproto.DERPFrameRecvPacket {
			continue
		}
		src, _, err := meshproto.SplitPacket(payload)
		return src, err == nil
	}
}

func TestRelayRefusesCrossMeshnet(t *testing.T) {
	c := newCoord(t)
	h := NewHub(slog.Default(), AuthConfig{Require: true, CoordPub: c.pub, Kind: meshproto.RelayKindPlatform})

	a, connA := joinMeshnet(t, h, c, 1)
	other, connOther := joinMeshnet(t, h, c, 2) // a node of ANOTHER org
	peer, connPeer := joinMeshnet(t, h, c, 1)   // same org as a (control)

	type got struct {
		src meshproto.NodeKey
		ok  bool
	}
	gotOther, gotPeer := make(chan got, 1), make(chan got, 1)
	go func() { s, ok := firstRelayed(connOther, 500*time.Millisecond); gotOther <- got{s, ok} }()
	go func() { s, ok := firstRelayed(connPeer, 2*time.Second); gotPeer <- got{s, ok} }()

	for _, dst := range []meshproto.NodeKey{other, peer} {
		if err := meshproto.WriteDERPFrame(connA, meshproto.DERPFrameSendPacket, meshproto.EncodePacket(dst, []byte("junk"))); err != nil {
			t.Fatalf("send: %v", err)
		}
	}

	if r := <-gotPeer; !r.ok || !r.src.Equal(a) {
		t.Fatalf("control: the same-meshnet peer did not receive the packet from a (ok=%v)", r.ok)
	}
	if r := <-gotOther; r.ok {
		t.Fatalf("CROSS-MESHNET: a node of meshnet 2 received a packet from meshnet 1 (src=%s)", r.src)
	}
	for _, d := range h.TakeUsage() {
		if d.Key.Equal(other) && d.BytesOut > 0 {
			t.Fatalf("meshnet 2 was billed %d egress bytes for traffic it never accepted", d.BytesOut)
		}
	}
}
