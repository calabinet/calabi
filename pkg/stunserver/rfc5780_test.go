package stunserver

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/calabinet/calabi/pkg/mesh-proto/stun"
)

func TestRFC5780Server_AllFourSocketResponses(t *testing.T) {
	srv, err := ListenRFC5780(RFC5780Config{
		PrimaryIP:   netip.MustParseAddr("127.0.0.1"),
		SecondaryIP: netip.MustParseAddr("127.0.0.2"),
	})
	if err != nil {
		t.Fatalf("ListenRFC5780: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen client udp4: %v", err)
	}
	defer pc.Close()

	primary := srv.PrimaryAddr()
	other := srv.OtherAddr()

	for _, tc := range []struct {
		name       string
		changeIP   bool
		changePort bool
		wantSrcIP  netip.Addr
		wantDiffPt bool
	}{
		{"plain", false, false, primary.Addr(), false},
		{"change_port", false, true, primary.Addr(), true},
		{"change_ip", true, false, other.Addr(), false},
		{"change_both", true, true, other.Addr(), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, _ := stun.NewTxID()
			req := stun.BindingRequestChange(tx, tc.changeIP, tc.changePort)
			if _, err := pc.WriteToUDPAddrPort(req, primary); err != nil {
				t.Fatalf("write: %v", err)
			}
			_ = pc.SetReadDeadline(time.Now().Add(time.Second))
			buf := make([]byte, 1500)
			n, from, err := pc.ReadFromUDPAddrPort(buf)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			detail, ok := stun.ParseBindingResponseDetail(buf[:n], tx)
			if !ok {
				t.Fatalf("response did not parse")
			}
			if detail.Other != other {
				t.Fatalf("OTHER-ADDRESS = %s, want %s", detail.Other, other)
			}
			if from.Addr().Unmap() != tc.wantSrcIP {
				t.Fatalf("reply src IP = %s, want %s", from.Addr(), tc.wantSrcIP)
			}
			if tc.wantDiffPt && from.Port() == primary.Port() {
				t.Fatalf("expected different reply port, got primary port %d", from.Port())
			}
			if !tc.wantDiffPt && !tc.changeIP && from.Port() != primary.Port() {
				t.Fatalf("expected primary port %d, got %d", primary.Port(), from.Port())
			}
		})
	}
}
