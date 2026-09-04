package relay

import (
	"log/slog"
	"net"
	"testing"
	"time"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// connectAuthed brings a node up through the full R0' handshake and returns its
// node-side conn. The grant helper (auth_test.go) stamps Meshnet=1, so a node
// connected this way is attributed to org 1.
func connectAuthed(t *testing.T, h *Hub, c coord, k meshproto.NodeKey, priv [meshproto.KeyLen]byte) net.Conn {
	t.Helper()
	mine, theirs := net.Pipe()
	t.Cleanup(func() { _ = mine.Close() })
	go h.Serve(theirs)
	if err := handshake(t, mine, k, priv, c.grant(t, k, meshproto.RelayScopeAll, time.Now().Add(time.Hour))); err != nil {
		t.Fatalf("authed connect handshake: %v", err)
	}
	eventually(t, connected(h, k, true), "authed node never registered")
	return mine
}

// drainUsage keeps taking deltas and merging them until cond is satisfied.
//
// Necessary because the hub increments AFTER the frame is on the wire: a test
// that observes the packet may still be a moment ahead of the accounting. That
// ordering is deliberate — bytes are counted once they are actually sent — and
// it means a single Take can split one packet's accounting across two calls,
// which a reporter merges anyway.
func drainUsage(t *testing.T, h *Hub, cond func(map[meshproto.NodeKey]UsageDelta) bool) map[meshproto.NodeKey]UsageDelta {
	t.Helper()
	got := map[meshproto.NodeKey]UsageDelta{}
	deadline := time.Now().Add(2 * time.Second)
	for {
		for _, d := range h.TakeUsage() {
			cur := got[d.Key]
			cur.Key = d.Key
			cur.Meshnet = d.Meshnet
			cur.BytesIn += d.BytesIn
			cur.BytesOut += d.BytesOut
			got[d.Key] = cur
		}
		if cond(got) {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for usage to settle; have %+v", got)
		}
		time.Sleep(time.Millisecond)
	}
}

// One relayed packet is counted twice on purpose — once as the sender's In and
// once as the receiver's Out. Both ends belong to the same org, so summing them
// would bill that org twice; picking the formula is the control plane's job, and
// it has to be able to change without redeploying relays.
func TestUsageCountsBothDirections(t *testing.T) {
	h := NewHub(slog.Default(), AuthConfig{})
	keyA, keyB := key(1), key(2)
	connA := connectClient(t, h, keyA)
	connB := connectClient(t, h, keyB)

	ciphertext := []byte("opaque-wireguard-encrypted-bytes")
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = meshproto.ReadDERPFrame(connB)
	}()
	if err := meshproto.WriteDERPFrame(connA, meshproto.DERPFrameSendPacket, meshproto.EncodePacket(keyB, ciphertext)); err != nil {
		t.Fatalf("send: %v", err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for the relayed packet")
	}

	n := uint64(len(ciphertext))
	got := drainUsage(t, h, func(m map[meshproto.NodeKey]UsageDelta) bool {
		return m[keyA].BytesIn == n && m[keyB].BytesOut == n
	})
	a, b := got[keyA], got[keyB]
	if a.BytesIn != uint64(len(ciphertext)) {
		t.Errorf("sender BytesIn = %d, want %d", a.BytesIn, len(ciphertext))
	}
	if a.BytesOut != 0 {
		t.Errorf("sender BytesOut = %d, want 0", a.BytesOut)
	}
	if b.BytesOut != uint64(len(ciphertext)) {
		t.Errorf("receiver BytesOut = %d, want %d", b.BytesOut, len(ciphertext))
	}
	if b.BytesIn != 0 {
		t.Errorf("receiver BytesIn = %d, want 0", b.BytesIn)
	}

	// Deltas, not gauges: what was reported once is not reported again.
	if got := h.TakeUsage(); len(got) != 0 {
		t.Errorf("second take returned %d deltas, want none", len(got))
	}
}

// A platform relay must be able to say WHOSE bytes it forwarded. The meshnet the
// node's grant proved rides onto its usage counter at auth time and out on every
// delta, so a per-org reporter can attribute the traffic — the relay itself never
// resolves a key to an org. Both ends here are org 1 (the grant helper's meshnet).
func TestUsageCarriesMeshnetFromGrant(t *testing.T) {
	c := newCoord(t)
	h := NewHub(slog.Default(), AuthConfig{Require: true, CoordPub: c.pub, Kind: meshproto.RelayKindPlatform})
	keyA, privA := nodeKeys(t)
	keyB, privB := nodeKeys(t)

	connA := connectAuthed(t, h, c, keyA, privA)
	connB := connectAuthed(t, h, c, keyB, privB)

	ciphertext := []byte("opaque-wireguard-encrypted-bytes")
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		_, _, _ = meshproto.ReadDERPFrame(connB)
	}()
	if err := meshproto.WriteDERPFrame(connA, meshproto.DERPFrameSendPacket, meshproto.EncodePacket(keyB, ciphertext)); err != nil {
		t.Fatalf("send: %v", err)
	}
	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for the relayed packet")
	}

	n := uint64(len(ciphertext))
	got := drainUsage(t, h, func(m map[meshproto.NodeKey]UsageDelta) bool {
		return m[keyA].BytesIn == n && m[keyB].BytesOut == n
	})
	if got[keyA].Meshnet != 1 {
		t.Errorf("sender delta Meshnet = %d, want 1", got[keyA].Meshnet)
	}
	if got[keyB].Meshnet != 1 {
		t.Errorf("receiver delta Meshnet = %d, want 1", got[keyB].Meshnet)
	}
}

// A packet the relay could not deliver cost the platform no egress, so it is not
// charged as any. The ingress that carried it still is.
func TestUndeliverablePacketIsNotChargedAsEgress(t *testing.T) {
	h := NewHub(slog.Default(), AuthConfig{})
	keyA, absent := key(1), key(9)
	connA := connectClient(t, h, keyA)

	ciphertext := []byte("goes-nowhere")
	if err := meshproto.WriteDERPFrame(connA, meshproto.DERPFrameSendPacket, meshproto.EncodePacket(absent, ciphertext)); err != nil {
		t.Fatalf("send: %v", err)
	}
	got := drainUsage(t, h, func(m map[meshproto.NodeKey]UsageDelta) bool {
		return m[keyA].BytesIn == uint64(len(ciphertext))
	})
	a := got[keyA]
	if a.BytesOut != 0 {
		t.Errorf("undeliverable packet was charged as egress: %d bytes", a.BytesOut)
	}
	if _, charged := got[absent]; charged {
		t.Fatal("a node that was never connected was charged")
	}
}

// Bytes relayed just before a drop exist nowhere else, so the counter has to
// outlive the connection. Once drained, a gone node's entry is dropped so a
// long-lived relay tracks live nodes rather than every node it ever saw.
func TestUsageOutlivesTheConnectionThenIsDropped(t *testing.T) {
	h := NewHub(slog.Default(), AuthConfig{})
	keyA, keyB := key(1), key(2)
	connA := connectClient(t, h, keyA)
	connB := connectClient(t, h, keyB)

	ciphertext := []byte("last-bytes-before-the-drop")
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = meshproto.ReadDERPFrame(connB)
	}()
	if err := meshproto.WriteDERPFrame(connA, meshproto.DERPFrameSendPacket, meshproto.EncodePacket(keyB, ciphertext)); err != nil {
		t.Fatalf("send: %v", err)
	}
	<-done

	_ = connA.Close()
	eventually(t, connected(h, keyA, false), "sender never disconnected")

	drained := drainUsage(t, h, func(m map[meshproto.NodeKey]UsageDelta) bool {
		return m[keyA].BytesIn == uint64(len(ciphertext))
	})
	if drained[keyA].BytesIn != uint64(len(ciphertext)) {
		t.Fatalf("bytes relayed before the drop were lost: got %d", drained[keyA].BytesIn)
	}
	// Deletion is one cycle behind the drain, on purpose: forward() adds to the
	// counter through a pointer AFTER releasing the hub lock, so an entry that
	// just yielded bytes might still receive more. Dropping it only once it
	// drains EMPTY gives those in-flight bytes somewhere to land.
	h.TakeUsage()
	h.mu.RLock()
	_, still := h.usage[keyA]
	h.mu.RUnlock()
	if still {
		t.Error("a drained counter for a disconnected node was kept")
	}
	// The one still connected keeps its counter — the client holds a pointer to
	// it, and deleting the entry underneath would orphan its next bytes.
	h.mu.RLock()
	_, kept := h.usage[keyB]
	h.mu.RUnlock()
	if !kept {
		t.Error("a connected node's counter was dropped")
	}
}
