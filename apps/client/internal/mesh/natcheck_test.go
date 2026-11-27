package mesh

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/calabinet/calabi/pkg/mesh-proto/stun"
)

func startFakeSTUN(t *testing.T, handler func(pc net.PacketConn, pkt []byte, from *net.UDPAddr)) (*net.UDPConn, string) {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp4: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pkt := append([]byte(nil), buf[:n]...)
			handler(pc, pkt, from)
		}
	}()
	t.Cleanup(func() {
		_ = pc.Close()
		<-done
	})
	return pc, pc.LocalAddr().String()
}

func TestCheckNAT_Stage1_ConeSymmetricAndBlocked(t *testing.T) {
	// Cone: two STUN servers report the exact same mapped address.
	mappedSame := netip.MustParseAddrPort("203.0.113.10:50000")
	_, s1 := startFakeSTUN(t, func(pc net.PacketConn, pkt []byte, from *net.UDPAddr) {
		if tx, ok := stun.IsBindingRequest(pkt); ok {
			_, _ = pc.WriteTo(stun.BindingResponse(tx, mappedSame), from)
		}
	})
	_, s2 := startFakeSTUN(t, func(pc net.PacketConn, pkt []byte, from *net.UDPAddr) {
		if tx, ok := stun.IsBindingRequest(pkt); ok {
			_, _ = pc.WriteTo(stun.BindingResponse(tx, mappedSame), from)
		}
	})

	rep := CheckNAT(context.Background(), NATCheckOptions{
		OverlayIP:          "100.64.0.9",
		STUNServers:        []string{s1, s2},
		AllowPublicSTUN:    false,
		AttemptTimeout:     150 * time.Millisecond,
		allowSameIPForTest: true,
	})
	if rep.NATType != NATCone || rep.HolePunch != HolePunchSupported {
		t.Fatalf("cone check: got %s / %s, want cone / supported (%+v)", rep.NATType, rep.HolePunch, rep)
	}
	if rep.PublicIP != "203.0.113.10" || rep.PublicPort != 50000 || rep.OverlayIP != "100.64.0.9" {
		t.Fatalf("unexpected fields: %+v", rep)
	}
	if rep.PortVaries == nil || *rep.PortVaries {
		t.Fatalf("expected port_varies=false, got %v", rep.PortVaries)
	}

	// Symmetric: second server sees a different mapped port.
	_, s3 := startFakeSTUN(t, func(pc net.PacketConn, pkt []byte, from *net.UDPAddr) {
		if tx, ok := stun.IsBindingRequest(pkt); ok {
			_, _ = pc.WriteTo(stun.BindingResponse(tx, netip.MustParseAddrPort("203.0.113.10:50099")), from)
		}
	})
	repSym := CheckNAT(context.Background(), NATCheckOptions{
		STUNServers:        []string{s1, s3},
		AllowPublicSTUN:    false,
		AttemptTimeout:     150 * time.Millisecond,
		allowSameIPForTest: true,
	})
	if repSym.NATType != NATSymmetric || repSym.HolePunch != HolePunchLimited {
		t.Fatalf("symmetric check: got %s / %s, want symmetric / limited", repSym.NATType, repSym.HolePunch)
	}
	if repSym.PortVaries == nil || !*repSym.PortVaries {
		t.Fatalf("expected port_varies=true, got %v", repSym.PortVaries)
	}

	// UDP blocked: silent STUN server.
	_, silent := startFakeSTUN(t, func(net.PacketConn, []byte, *net.UDPAddr) {})
	repBlk := CheckNAT(context.Background(), NATCheckOptions{
		STUNServers:        []string{silent},
		AllowPublicSTUN:    false,
		AttemptTimeout:     80 * time.Millisecond,
		allowSameIPForTest: true,
	})
	if repBlk.NATType != NATUDPBlocked || repBlk.HolePunch != HolePunchBlocked {
		t.Fatalf("blocked check: got %s / %s, want udp_blocked / blocked", repBlk.NATType, repBlk.HolePunch)
	}
}

func TestCheckNAT_Stage2_RFC5780_FullRestrictedPortRestricted(t *testing.T) {
	mapped := netip.MustParseAddrPort("198.51.100.7:41000")

	runMode := func(t *testing.T, answerChangeBoth, answerChangePort bool) NATReport {
		t.Helper()
		var mu sync.Mutex
		altPortPC, _ := startFakeSTUN(t, func(net.PacketConn, []byte, *net.UDPAddr) {})
		otherPC, otherAddr := startFakeSTUN(t, func(pc net.PacketConn, pkt []byte, from *net.UDPAddr) {
			if tx, ok := stun.IsBindingRequest(pkt); ok {
				_, _ = pc.WriteTo(stun.BindingResponse(tx, mapped), from)
			}
		})
		otherAP := netip.MustParseAddrPort(otherAddr)

		_, primaryAddr := startFakeSTUN(t, func(pc net.PacketConn, pkt []byte, from *net.UDPAddr) {
			tx, changeIP, changePort, ok := stun.ParseChangeRequest(pkt)
			if !ok {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			switch {
			case changeIP && changePort:
				if answerChangeBoth {
					_, _ = otherPC.WriteTo(stun.BindingResponseWithOther(tx, mapped, otherAP), from)
				}
			case !changeIP && changePort:
				if answerChangePort {
					_, _ = altPortPC.WriteTo(stun.BindingResponseWithOther(tx, mapped, otherAP), from)
				}
			default:
				_, _ = pc.WriteTo(stun.BindingResponseWithOther(tx, mapped, otherAP), from)
			}
		})

		return CheckNAT(context.Background(), NATCheckOptions{
			RFC5780Servers:     []string{primaryAddr},
			AllowPublicSTUN:    false,
			AttemptTimeout:     80 * time.Millisecond,
			allowSameIPForTest: true,
		})
	}

	r1 := runMode(t, true, true)
	if r1.NATType != NATFullCone || r1.HolePunch != HolePunchDirect || r1.ProbeSource != "calabi_rfc5780" {
		t.Fatalf("NAT1: got %+v", r1)
	}
	r2 := runMode(t, false, true)
	if r2.NATType != NATRestrictedCone || r2.HolePunch != HolePunchSupported || r2.ProbeSource != "calabi_rfc5780" {
		t.Fatalf("NAT2: got %+v", r2)
	}
	r3 := runMode(t, false, false)
	if r3.NATType != NATPortRestrictedCone || r3.HolePunch != HolePunchSupported || r3.ProbeSource != "calabi_rfc5780" {
		t.Fatalf("NAT3: got %+v", r3)
	}
}

func TestCheckNAT_Stage2DegradesCleanlyToCone(t *testing.T) {
	mappedSame := netip.MustParseAddrPort("203.0.113.55:51000")
	_, s1 := startFakeSTUN(t, func(pc net.PacketConn, pkt []byte, from *net.UDPAddr) {
		if tx, ok := stun.IsBindingRequest(pkt); ok {
			_, _ = pc.WriteTo(stun.BindingResponse(tx, mappedSame), from)
		}
	})
	_, s2 := startFakeSTUN(t, func(pc net.PacketConn, pkt []byte, from *net.UDPAddr) {
		if tx, ok := stun.IsBindingRequest(pkt); ok {
			_, _ = pc.WriteTo(stun.BindingResponse(tx, mappedSame), from)
		}
	})
	_, silent5780 := startFakeSTUN(t, func(net.PacketConn, []byte, *net.UDPAddr) {})

	rep := CheckNAT(context.Background(), NATCheckOptions{
		STUNServers:        []string{s1, s2},
		RFC5780Servers:     []string{silent5780},
		AllowPublicSTUN:    false,
		AttemptTimeout:     80 * time.Millisecond,
		allowSameIPForTest: true,
	})
	if rep.NATType != NATCone || rep.HolePunch != HolePunchSupported || rep.ProbeSource != "edge" {
		t.Fatalf("expected graceful degradation to cone, got %+v", rep)
	}
}

func TestCheckNAT_SelfHostedNeverUsesPublicSTUN(t *testing.T) {
	rep := CheckNAT(context.Background(), NATCheckOptions{
		AllowPublicSTUN: false,
		AttemptTimeout:  50 * time.Millisecond,
	})
	if rep.NATType != NATUnknown || rep.Detail != "no_stun_servers" {
		t.Fatalf("self-hosted with 0 servers: got %+v", rep)
	}
}
