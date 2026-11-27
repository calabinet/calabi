package stunserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"

	"github.com/calabinet/calabi/pkg/mesh-proto/stun"
)

// RFC5780Config configures a dual-IP, dual-port RFC 5780 STUN server capable of
// answering CHANGE-REQUEST (ChangeIP / ChangePort) and advertising OTHER-ADDRESS
// so clients can classify NAT1 (Full Cone), NAT2 (Restricted Cone), NAT3
// (Port-Restricted Cone), and NAT4 (Symmetric) without third-party STUN.
type RFC5780Config struct {
	// PrimaryIP and SecondaryIP are the two local IPv4 addresses to bind.
	PrimaryIP   netip.Addr
	SecondaryIP netip.Addr
	// PrimaryPort and SecondaryPort are the two UDP ports to bind on each IP
	// (typically 3478 and 3479). If zero in tests, the OS assigns ephemeral ports.
	PrimaryPort   uint16
	SecondaryPort uint16
	// AdvertisePrimaryIP and AdvertiseSecondaryIP optionally override the IPs
	// advertised in OTHER-ADDRESS when running on a cloud VM where two Elastic
	// IPs (EIPs) are 1:1 NAT-mapped to two private NIC IPv4 addresses.
	AdvertisePrimaryIP   netip.Addr
	AdvertiseSecondaryIP netip.Addr
	Logger               *slog.Logger
}

// RFC5780Server binds four UDP4 sockets:
//   - (PrimaryIP, PrimaryPort)
//   - (PrimaryIP, SecondaryPort)
//   - (SecondaryIP, PrimaryPort)
//   - (SecondaryIP, SecondaryPort)
type RFC5780Server struct {
	conns  [2][2]*net.UDPConn
	advIP  [2]netip.Addr
	ports  [2][2]uint16
	logger *slog.Logger

	closeOnce sync.Once
	wg        sync.WaitGroup
}

// ListenRFC5780 opens all four UDP sockets for an RFC 5780 STUN server.
func ListenRFC5780(cfg RFC5780Config) (*RFC5780Server, error) {
	if !cfg.PrimaryIP.IsValid() || !cfg.PrimaryIP.Unmap().Is4() {
		return nil, fmt.Errorf("stunserver: invalid primary IPv4: %v", cfg.PrimaryIP)
	}
	if !cfg.SecondaryIP.IsValid() || !cfg.SecondaryIP.Unmap().Is4() {
		return nil, fmt.Errorf("stunserver: invalid secondary IPv4: %v", cfg.SecondaryIP)
	}
	p1 := cfg.PrimaryIP.Unmap()
	p2 := cfg.SecondaryIP.Unmap()
	if p1 == p2 {
		return nil, errors.New("stunserver: primary and secondary IPv4 must be distinct")
	}
	if cfg.PrimaryPort != 0 && cfg.SecondaryPort != 0 && cfg.PrimaryPort == cfg.SecondaryPort {
		return nil, errors.New("stunserver: primary and secondary UDP ports must be distinct")
	}

	adv1 := p1
	if cfg.AdvertisePrimaryIP.IsValid() {
		adv1 = cfg.AdvertisePrimaryIP.Unmap()
		if !adv1.Is4() {
			return nil, fmt.Errorf("stunserver: invalid advertise primary IPv4: %v", cfg.AdvertisePrimaryIP)
		}
	}
	adv2 := p2
	if cfg.AdvertiseSecondaryIP.IsValid() {
		adv2 = cfg.AdvertiseSecondaryIP.Unmap()
		if !adv2.Is4() {
			return nil, fmt.Errorf("stunserver: invalid advertise secondary IPv4: %v", cfg.AdvertiseSecondaryIP)
		}
	}
	if adv1 == adv2 {
		return nil, errors.New("stunserver: advertised primary and secondary IPv4 must be distinct")
	}

	s := &RFC5780Server{
		advIP:  [2]netip.Addr{adv1, adv2},
		logger: cfg.Logger,
	}
	bindIPs := [2]netip.Addr{p1, p2}
	bindPorts := [2]uint16{cfg.PrimaryPort, cfg.SecondaryPort}

	cleanup := func() {
		for i := range 2 {
			for j := range 2 {
				if s.conns[i][j] != nil {
					_ = s.conns[i][j].Close()
				}
			}
		}
	}

	for i := range 2 {
		for j := range 2 {
			addr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(bindIPs[i], bindPorts[j]))
			c, err := net.ListenUDP("udp4", addr)
			if err != nil {
				cleanup()
				return nil, fmt.Errorf("stunserver: listen %s: %w", addr.String(), err)
			}
			s.conns[i][j] = c
			s.ports[i][j] = uint16(c.LocalAddr().(*net.UDPAddr).Port)
		}
	}
	return s, nil
}

// PrimaryAddr returns the bound primary (IP1:Port1) address.
func (s *RFC5780Server) PrimaryAddr() netip.AddrPort {
	return s.conns[0][0].LocalAddr().(*net.UDPAddr).AddrPort()
}

// OtherAddr returns the advertised OTHER-ADDRESS corresponding to PrimaryAddr.
func (s *RFC5780Server) OtherAddr() netip.AddrPort {
	return netip.AddrPortFrom(s.advIP[1], s.ports[1][1])
}

// Serve runs all four UDP read loops until ctx is cancelled or Close is called.
func (s *RFC5780Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()
	for i := range 2 {
		for j := range 2 {
			s.wg.Add(1)
			go func(ipIdx, portIdx int) {
				defer s.wg.Done()
				s.serveSocket(ipIdx, portIdx)
			}(i, j)
		}
	}
	s.wg.Wait()
	return nil
}

// Close stops all four UDP listeners.
func (s *RFC5780Server) Close() error {
	s.closeOnce.Do(func() {
		for i := range 2 {
			for j := range 2 {
				if s.conns[i][j] != nil {
					_ = s.conns[i][j].Close()
				}
			}
		}
	})
	return nil
}

func (s *RFC5780Server) serveSocket(ipIdx, portIdx int) {
	conn := s.conns[ipIdx][portIdx]
	otherIPIdx := 1 - ipIdx
	otherPortIdx := 1 - portIdx
	otherAddr := netip.AddrPortFrom(s.advIP[otherIPIdx], s.ports[otherIPIdx][otherPortIdx])

	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		tx, changeIP, changePort, ok := stun.ParseChangeRequest(buf[:n])
		if !ok {
			continue
		}
		replyIPIdx := ipIdx
		if changeIP {
			replyIPIdx = otherIPIdx
		}
		replyPortIdx := portIdx
		if changePort {
			replyPortIdx = otherPortIdx
		}
		reflexive := netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		resp := stun.BindingResponseWithOther(tx, reflexive, otherAddr)
		replyConn := s.conns[replyIPIdx][replyPortIdx]
		if _, err := replyConn.WriteToUDPAddrPort(resp, from); err != nil && s.logger != nil {
			s.logger.Debug("stun5780: write response failed", "to", from.String(), "err", err)
		}
	}
}
