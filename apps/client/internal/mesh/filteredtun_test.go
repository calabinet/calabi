package mesh

import (
	"net/netip"
	"os"
	"testing"

	"golang.zx2c4.com/wireguard/tun"
)

// fakeTUN records what actually reached the OS.
type fakeTUN struct {
	written [][]byte
}

func (f *fakeTUN) File() *os.File                         { return nil }
func (f *fakeTUN) Read([][]byte, []int, int) (int, error) { return 0, nil }
func (f *fakeTUN) MTU() (int, error)                      { return 1280, nil }
func (f *fakeTUN) Name() (string, error)                  { return "fake0", nil }
func (f *fakeTUN) Events() <-chan tun.Event               { return nil }
func (f *fakeTUN) Close() error                           { return nil }
func (f *fakeTUN) BatchSize() int                         { return 4 }
func (f *fakeTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		f.written = append(f.written, append([]byte(nil), b[offset:]...))
	}
	return len(bufs), nil
}

// The wrap only drops INBOUND packets a rule doesn't allow, and a drop in the
// middle of a batch must not cost the packets after it.
func TestFilteredTUNDropsOnlyDisallowed(t *testing.T) {
	inner := &fakeTUN{}
	f := &PacketFilter{}
	f.SetRules(true, []FilterRule{{
		SrcCIDRs: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
		DstPorts: []PortRange{{First: 443, Last: 443, Proto: "tcp"}},
	}})
	ft := newFilteredTUN(inner, f, nil)

	allowed := ipv4("100.64.0.1", protoTCP, 443, 0)
	denied := ipv4("100.64.0.9", protoTCP, 443, 0)
	batch := [][]byte{allowed, denied, allowed}

	n, err := ft.Write(batch, 0)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	// WireGuard must see the whole batch as handled — the device is what dropped
	// the packet, not a failed write.
	if n != 3 {
		t.Fatalf("reported %d written, want the full batch of 3", n)
	}
	if len(inner.written) != 2 {
		t.Fatalf("%d packets reached the OS, want the 2 allowed ones", len(inner.written))
	}
}

// With filtering off the wrap is a pass-through (no copying, no dropping).
func TestFilteredTUNPassThroughWhenDisabled(t *testing.T) {
	inner := &fakeTUN{}
	ft := newFilteredTUN(inner, &PacketFilter{}, nil)
	n, err := ft.Write([][]byte{ipv4("203.0.113.1", protoTCP, 22, 0)}, 0)
	if err != nil || n != 1 || len(inner.written) != 1 {
		t.Fatalf("pass-through failed: n=%d err=%v written=%d", n, err, len(inner.written))
	}
}

// Everything filtered: the batch is still reported as consumed, and nothing
// reaches the OS.
func TestFilteredTUNAllDropped(t *testing.T) {
	inner := &fakeTUN{}
	f := &PacketFilter{}
	f.SetRules(true, nil) // enabled, no rules = deny all
	ft := newFilteredTUN(inner, f, nil)
	n, err := ft.Write([][]byte{ipv4("100.64.0.1", protoTCP, 443, 0)}, 0)
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v, want the batch reported as handled", n, err)
	}
	if len(inner.written) != 0 {
		t.Fatalf("%d packets reached the OS, want none", len(inner.written))
	}
}
