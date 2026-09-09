package meshproto

import (
	"bytes"
	"testing"
)

// A frame must reach the transport as ONE write.
//
// Two writes (5-byte header, then payload) is what this used to do, and on a TCP
// relay link it puts a tiny segment ahead of every packet — a pattern that can
// serialise the stream into one frame per round trip when it meets Nagle or a
// delayed ACK. A live link measured 2.7 Mbit/s where iperf3 on the same path did
// 20. Loopback tests could never catch it: with no RTT the segments coalesce and
// the cost vanishes. So the invariant has to be asserted structurally instead.
type countingWriter struct {
	writes int
	buf    bytes.Buffer
}

func (c *countingWriter) Write(p []byte) (int, error) {
	c.writes++
	return c.buf.Write(p)
}

func TestWriteDERPFrameIsASingleWrite(t *testing.T) {
	for _, n := range []int{0, 1, 1280, MaxDERPFrameLen} {
		var w countingWriter
		if err := WriteDERPFrame(&w, DERPFrameSendPacket, make([]byte, n)); err != nil {
			t.Fatalf("payload %d: %v", n, err)
		}
		if w.writes != 1 {
			t.Errorf("payload %d: %d writes, want exactly 1", n, w.writes)
		}
		if got := w.buf.Len(); got != 5+n {
			t.Errorf("payload %d: wrote %d bytes, want %d", n, got, 5+n)
		}
		// And it still round-trips.
		typ, back, err := ReadDERPFrame(&w.buf)
		if err != nil {
			t.Fatalf("payload %d: read back: %v", n, err)
		}
		if typ != DERPFrameSendPacket || len(back) != n {
			t.Errorf("payload %d: round-tripped as type %v len %d", n, typ, len(back))
		}
	}
}
