package mobile

import (
	"errors"
	"os"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"
)

func readOne(t *testing.T, s *swapTUN) (chan []byte, chan error) {
	t.Helper()
	pkts, errs := make(chan []byte, 1), make(chan error, 1)
	go func() {
		bufs := [][]byte{make([]byte, 1500)}
		sizes := make([]int, 1)
		n, err := s.Read(bufs, sizes, 0)
		if err != nil {
			errs <- err
			return
		}
		if n == 1 {
			pkts <- bufs[0][:sizes[0]]
		}
	}()
	return pkts, errs
}

// Before the VPN exists there is no device: a read waits for one, and a write
// has nowhere to go and is dropped rather than failing WireGuard.
func TestSwapTUNBeforeTheFirstDevice(t *testing.T) {
	s := newSwapTUN(1280)
	defer s.Close()

	if n, err := s.Write([][]byte{make([]byte, 20)}, 0); n != 1 || err != nil {
		t.Fatalf("Write with no device = %d, %v; want the packet dropped silently", n, err)
	}
	pkts, errs := readOne(t, s)
	select {
	case <-pkts:
		t.Fatal("Read returned a packet with no device")
	case err := <-errs:
		t.Fatalf("Read failed with no device: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	ch := tuntest.NewChannelTUN()
	if err := s.Swap(ch.TUN()); err != nil {
		t.Fatal(err)
	}
	ch.Outbound <- []byte("first")
	select {
	case p := <-pkts:
		if string(p) != "first" {
			t.Fatalf("read %q", p)
		}
	case err := <-errs:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("the waiting Read never got the first device's packet")
	}
}

// Re-establishing the VPN swaps the device under a Read that is blocked on the
// old one. WireGuard must not see that as the tun failing — it would shut the
// device down — so the Read carries on with the new device.
func TestSwapTUNCarriesABlockedReadOver(t *testing.T) {
	s := newSwapTUN(1280)
	defer s.Close()
	old := tuntest.NewChannelTUN()
	if err := s.Swap(old.TUN()); err != nil {
		t.Fatal(err)
	}
	pkts, errs := readOne(t, s)
	time.Sleep(20 * time.Millisecond) // let the Read block on the old device

	next := tuntest.NewChannelTUN()
	if err := s.Swap(next.TUN()); err != nil {
		t.Fatal(err)
	}
	next.Outbound <- []byte("after-swap")
	select {
	case p := <-pkts:
		if string(p) != "after-swap" {
			t.Fatalf("read %q", p)
		}
	case err := <-errs:
		t.Fatalf("Read surfaced the swap as an error: %v", err)
	case <-time.After(time.Second):
		t.Fatal("Read never moved to the new device")
	}

	// Writes go to the new device too. (Its inbound channel is unbuffered, so
	// the write only completes once something receives.)
	wrote := make(chan error, 1)
	go func() {
		_, err := s.Write([][]byte{[]byte("out")}, 0)
		wrote <- err
	}()
	select {
	case p := <-next.Inbound:
		if string(p) != "out" {
			t.Fatalf("wrote %q", p)
		}
	case <-time.After(time.Second):
		t.Fatal("write did not reach the new device")
	}
	if err := <-wrote; err != nil {
		t.Fatal(err)
	}
}

func TestSwapTUNCloseEndsARead(t *testing.T) {
	s := newSwapTUN(1280)
	_, errs := readOne(t, s)
	time.Sleep(20 * time.Millisecond)
	s.Close()
	select {
	case err := <-errs:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("Read after Close = %v, want os.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not end the blocked Read")
	}
	if err := s.Swap(tuntest.NewChannelTUN().TUN()); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Swap after Close = %v, want os.ErrClosed", err)
	}
}
