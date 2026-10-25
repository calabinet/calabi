package filetransfer

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestRevocationDuringPathWaitDoesNotReadSource(t *testing.T) {
	var allowed atomic.Bool
	allowed.Store(true)
	p, _ := NewPacer(DefaultDeviceKbps)
	src := bytes.NewReader([]byte("private source"))
	r := &pacedReader{ctx: context.Background(), src: src, pacer: p, allowed: allowed.Load, extraWait: func(context.Context, int) error { allowed.Store(false); return nil }}
	if n, err := r.Read(make([]byte, 4)); n != 0 || err == nil {
		t.Fatalf("revoked source read: n=%d error=%v", n, err)
	}
	if src.Len() != len("private source") {
		t.Fatal("source consumed after revocation")
	}
}

func TestAgentPathBudgetsAndLiveTransition(t *testing.T) {
	ip := netip.MustParseAddr("127.0.0.1")
	id, _ := NewIdentity()
	other, _ := NewIdentity()
	var route atomic.Value
	route.Store("direct")
	a, err := NewAgent(AgentConfig{Identity: id, Directory: t.TempDir(), Scope: "budget", LocalIP: ip, Port: 17401, Kbps: DefaultDeviceKbps, MaxBytes: 8 << 20,
		Resolve: func(netip.Addr) (Grant, bool) {
			return Grant{Path: route.Load().(string), Peer: Peer{IP: ip, Fingerprint: other.Fingerprint}, DeviceKey: "other", Port: 17401, Receiving: true}, true
		}, Incoming: func(netip.Addr, uint16) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	a.ApplyKnownRelayLimit(8192)
	if a.budget.Ceiling() != DefaultDeviceKbps || a.relayBudget.Kbps() != 6144 {
		t.Fatal("relay quota poisoned direct budget or failed to lift fallback")
	}
	a.ApplyKnownRelayLimit(0)
	if a.relayBudget.Kbps() != 6144 {
		t.Fatal("missing metadata replaced known quota")
	}
	a.ApplyKnownRelayLimit(^uint32(0))
	if a.relayBudget.Kbps() != DefaultDeviceKbps {
		t.Fatal("large quota overflowed platform int or escaped configured ceiling")
	}
	a.ApplyKnownRelayLimit(8192)
	s, err := a.Sender(ip)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.flow.Kbps() != InitialKbps || a.pathBudget(ip) != nil {
		t.Fatal("direct did not start independently")
	}
	for n := 0; n < 8; n++ {
		s.flow.Observe(5*time.Millisecond, false)
	}
	if s.flow.Kbps() <= InitialKbps {
		t.Fatal("healthy path never ramps up")
	}
	a.ApplyKnownRelayLimit(8) // 6 kbps: next source read must not use direct rate.
	route.Store("relay")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := s.waitPath(ctx, 8192); err == nil {
		t.Fatal("direct-to-relay change bypassed rate gate")
	}
	if s.flow.Ceiling() != 6 {
		t.Fatal("flow retained direct ceiling")
	}
	if a.pathBudget(ip) != a.pathBudget(netip.MustParseAddr("127.0.0.2")) {
		t.Fatal("relay peers received independent device allowances")
	}
	g, _ := a.cfg.Resolve(ip)
	r, err := a.receiver(g, true)
	if err != nil {
		t.Fatal(err)
	}
	legacy := &receiveSession{Transfer: Transfer{Kbps: 512, MaxBlock: paceChunk}}
	legacy.publish()
	if got := r.receiver.visible(legacy); got.Kbps != 6 || got.MaxBlock != paceChunk {
		t.Fatalf("relay receive limit: %+v", got)
	}
	route.Store("")
	if a.pathBudget(ip) == nil {
		t.Fatal("unknown path escaped relay budget")
	}
	route.Store("direct")
	if got := r.receiver.visible(legacy); got.Kbps != DefaultDeviceKbps || got.MaxBlock != BlockSize {
		t.Fatalf("direct receive stuck at persisted relay/legacy limit: %+v", got)
	}
	if err := s.waitPath(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	s.flow.Observe(5*time.Millisecond, false)
	if s.flow.Ceiling() != DefaultDeviceKbps || s.flow.Kbps() <= 6 {
		t.Fatal("return to direct could not recover")
	}
}

func TestDirectTransferExceedsLegacy512Kbps(t *testing.T) {
	ip := netip.MustParseAddr("127.0.0.1")
	senderID, _ := NewIdentity()
	receiverID, _ := NewIdentity()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	r, err := NewAgent(AgentConfig{Identity: receiverID, Directory: t.TempDir(), Scope: "receive", LocalIP: ip, Port: port, Kbps: DefaultDeviceKbps, MaxBytes: 8 << 20,
		Resolve: func(netip.Addr) (Grant, bool) {
			return Grant{Path: "direct", Peer: Peer{IP: ip, Fingerprint: senderID.Fingerprint}, DeviceKey: "sender", Port: port}, true
		}, Incoming: func(netip.Addr, uint16) bool { return true }})
	if err != nil {
		l.Close()
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.Serve(l); err != nil {
		t.Fatal(err)
	}
	r.SetReceiving(true)
	a, err := NewAgent(AgentConfig{Identity: senderID, Directory: t.TempDir(), Scope: "send", LocalIP: ip, Port: 17401, Kbps: DefaultDeviceKbps, MaxBytes: 8 << 20,
		Resolve: func(netip.Addr) (Grant, bool) {
			return Grant{Path: "direct", Peer: Peer{IP: ip, Fingerprint: receiverID.Fingerprint}, DeviceKey: "receiver", Port: port, Receiving: true}, true
		}, Incoming: func(netip.Addr, uint16) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	// A low relay quota must not constrain this direct transfer in either direction.
	a.ApplyKnownRelayLimit(8)
	r.ApplyKnownRelayLimit(8)
	s, err := a.Sender(ip)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	accepted := make(chan error, 1)
	go func() {
		for ctx.Err() == nil {
			list := r.List()
			if len(list) > 0 {
				accepted <- r.Decide([]string{list[0].Transfer.ID}, true)
				return
			}
			time.Sleep(time.Millisecond)
		}
		accepted <- ctx.Err()
	}()
	data := bytes.Repeat([]byte("abcd"), 256*1024)
	var ticket BatchTicket
	if err := s.SendBatch(ctx, []Source{{Reader: bytes.NewReader(data), Name: "direct.bin", Size: int64(len(data))}}, &ticket, func(BatchTicket) error { return nil }, nil); err != nil {
		t.Fatal(err)
	}
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	if err := r.CopyCompleted(ctx, r.List()[0].Transfer.ID, &got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), data) {
		t.Fatal("direct bytes differ")
	}
}
