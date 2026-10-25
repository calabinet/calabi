package filetransfer

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestPeerReceiveLimitDoesNotPoisonSharedDeviceBudget(t *testing.T) {
	ip := netip.MustParseAddr("127.0.0.1")
	a, _ := NewIdentity()
	b, _ := NewIdentity()
	remoteBudget, _ := NewPacer(512)
	remoteBudget.SetDeviceLimit(8)
	r, err := NewReceiver(ReceiverConfig{Peer: Peer{IP: ip, Fingerprint: a.Fingerprint}, Directory: t.TempDir(), Kbps: 512, MaxBytes: 8 << 20, Budget: remoteBudget, Allowed: func() bool { return true }, Durable: true, Scope: "remote"})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	srv, done := r.Serve(l, b)
	defer func() { srv.Close(); <-done }()
	localBudget, _ := NewPacer(512)
	s, err := NewBatchSender(a, ip, Peer{IP: ip, Fingerprint: b.Fingerprint}, l.Addr().(*net.TCPAddr).Port, localBudget, func() bool { return true }, "local")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accepted := make(chan error, 1)
	go func() {
		for ctx.Err() == nil {
			list := r.List()
			if len(list) == 1 {
				accepted <- r.Decide(list[0].ID, true)
				return
			}
			time.Sleep(time.Millisecond)
		}
		accepted <- ctx.Err()
	}()
	var ticket BatchTicket
	var receiveKbps int
	if err := s.SendBatch(ctx, []Source{{Reader: bytes.NewReader(nil), Name: "zero.bin", Size: 0}}, &ticket, func(BatchTicket) error { return nil }, func(p BatchProgress) { receiveKbps = p.Transfer.Kbps }); err != nil {
		t.Fatal(err)
	}
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
	if receiveKbps != 8 {
		t.Fatalf("known receiver limit not negotiated: %d", receiveKbps)
	}
	if localBudget.Ceiling() != 512 {
		t.Fatal("a slow recipient lowered all later device transfers")
	}
}

func TestPreparationCanBeCancelledWithoutStoppingWorkspace(t *testing.T) {
	id, _ := NewIdentity()
	cfg := AgentConfig{Identity: id, Directory: t.TempDir(), Scope: "one", LocalIP: netip.MustParseAddr("127.0.0.1"), Port: 17401, Kbps: 512, MaxBytes: 1 << 20, Resolve: func(netip.Addr) (Grant, bool) { return Grant{}, false }, Incoming: func(netip.Addr, uint16) bool { return false }}
	w, err := NewWorkspace(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if second, err := NewWorkspace(cfg); err == nil {
		second.Close()
		t.Fatal("two agents opened one private workspace")
	}
	reader, writer := io.Pipe()
	defer writer.Close()
	done := make(chan error, 1)
	go func() { _, err := w.Stage(context.Background(), reader, "document", -1); done <- err }()
	deadline := time.Now().Add(time.Second)
	for !w.Preparing() {
		if time.Now().After(deadline) {
			t.Fatal("preparation did not start")
		}
		time.Sleep(time.Millisecond)
	}
	w.CancelPreparation()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled stream staged as complete")
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not interrupt a blocked document read")
	}
	if len(w.Staged()) != 0 {
		t.Fatal("partial document was retained as a source")
	}
	if _, err := w.Stage(context.Background(), bytes.NewReader([]byte("ok")), "next.txt", 2); err != nil {
		t.Fatal("cancel stopped future preparations", err)
	}
}
