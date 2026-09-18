package mobile

import (
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// swapTUN is the tun device WireGuard sees on a phone: a stable front for a
// device that changes underneath it.
//
// Android hands a VPN its addresses and routes all at once, and changing any of
// them means establishing the VPN again, which yields a NEW file descriptor. A wireguard-go Device cannot switch
// tun devices, so it gets this instead: Swap installs the new one and closes the
// old, and a read or write that failed because its device was swapped away is
// retried on the replacement instead of being reported — WireGuard would take
// that error as the tun dying and shut the whole device down.
//
// It also exists before the first device does: the VPN can only be established
// once the coordinator has assigned an address, which happens after the
// datapath is up. Until then reads wait and writes are dropped.
type swapTUN struct {
	mtu int

	mu      sync.Mutex
	dev     tun.Device // nil until the platform first establishes the VPN
	gen     uint64     // bumped on every Swap
	changed chan struct{}
	closed  bool

	events chan tun.Event
}

func newSwapTUN(mtu int) *swapTUN {
	return &swapTUN{mtu: mtu, changed: make(chan struct{}), events: make(chan tun.Event, 1)}
}

// Swap makes dev the device all I/O goes to and closes the previous one. After
// Close it closes dev instead and reports os.ErrClosed.
func (s *swapTUN) Swap(dev tun.Device) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = dev.Close()
		return os.ErrClosed
	}
	old := s.dev
	s.dev = dev
	s.gen++
	close(s.changed)
	s.changed = make(chan struct{})
	s.mu.Unlock()
	// Closed only after the new device is in place, so a reader woken by this
	// close already finds the generation moved on and retries rather than failing.
	if old != nil {
		_ = old.Close()
	}
	return nil
}

func (s *swapTUN) current() (dev tun.Device, gen uint64, changed <-chan struct{}, closed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dev, s.gen, s.changed, s.closed
}

// swappedSince reports whether the device of generation gen has been replaced.
func (s *swapTUN) swappedSince(gen uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed || s.gen != gen
}

func (s *swapTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for {
		dev, gen, changed, closed := s.current()
		if closed {
			return 0, os.ErrClosed
		}
		if dev == nil {
			<-changed
			continue
		}
		n, err := dev.Read(bufs, sizes, offset)
		if err != nil && s.swappedSince(gen) {
			continue
		}
		return n, err
	}
}

func (s *swapTUN) Write(bufs [][]byte, offset int) (int, error) {
	for {
		dev, gen, _, closed := s.current()
		if closed {
			return 0, os.ErrClosed
		}
		if dev == nil {
			// Nowhere to deliver yet: nothing on this device routes to the mesh
			// before the VPN exists, so nothing is waiting for these packets.
			return len(bufs), nil
		}
		n, err := dev.Write(bufs, offset)
		if err != nil && s.swappedSince(gen) {
			continue
		}
		return n, err
	}
}

func (s *swapTUN) MTU() (int, error) {
	if dev, _, _, _ := s.current(); dev != nil {
		return dev.MTU()
	}
	return s.mtu, nil
}

func (s *swapTUN) Name() (string, error) {
	if dev, _, _, _ := s.current(); dev != nil {
		return dev.Name()
	}
	return "tun", nil
}

// File is nil: there is no single file behind a device that changes.
func (s *swapTUN) File() *os.File { return nil }

// Events never fires. A phone's VPN reports up/down/MTU to the app, not to the
// datapath, and the datapath is brought up explicitly.
func (s *swapTUN) Events() <-chan tun.Event { return s.events }

// BatchSize is 1, what a tun opened from a VpnService descriptor supports, and
// must not change over the device's life.
func (s *swapTUN) BatchSize() int { return 1 }

func (s *swapTUN) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	dev := s.dev
	s.dev = nil
	close(s.changed)
	close(s.events)
	s.mu.Unlock()
	if dev != nil {
		return dev.Close()
	}
	return nil
}
