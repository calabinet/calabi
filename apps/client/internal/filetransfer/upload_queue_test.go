package filetransfer

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func queuedUploadFixture(t *testing.T) (*Receiver, *BatchSender, chan struct{}) {
	t.Helper()
	a, _ := NewIdentity()
	b, _ := NewIdentity()
	ip := netip.MustParseAddr("127.0.0.1")
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	r, err := NewReceiver(ReceiverConfig{Peer: Peer{IP: ip, Fingerprint: a.Fingerprint}, Directory: t.TempDir(), Kbps: 32768, MaxBytes: 1 << 20, Allowed: func() bool { return true }, Durable: true, Scope: "queue", UploadGate: gate})
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, served := r.Serve(l, b)
	pacer, _ := NewPacer(32768)
	s, err := NewBatchSender(a, ip, Peer{IP: ip, Fingerprint: b.Fingerprint}, l.Addr().(*net.TCPAddr).Port, pacer, func() bool { return true }, "queue-sender")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close(); srv.Close(); <-served; r.Close() })
	return r, s, gate
}

// Holding the shared gate models a different device uploading a slow block.
// A healthy sender must wait rather than exhaust its no-progress retries.
func TestReceiverQueuesBehindAnotherUpload(t *testing.T) {
	r, s, gate := queuedUploadFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	data := []byte("queued upload remains intact")
	var ticket BatchTicket
	done := make(chan error, 1)
	go func() {
		done <- s.SendBatch(ctx, []Source{{Reader: bytes.NewReader(data), Name: "queued.bin", Size: int64(len(data))}}, &ticket, func(BatchTicket) error { return nil }, nil)
	}()
	syncUntil(t, func() bool { return len(r.List()) == 1 })
	id := r.List()[0].ID
	if err := r.Decide(id, true); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		t.Fatalf("another device's active upload stopped a healthy sender: %v", err)
	case <-time.After(4 * time.Second):
	}
	if r.List()[0].Offset != 0 {
		t.Fatal("queued upload consumed bytes before admission")
	}
	<-gate
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("queued upload did not complete after admission")
	}
	var actual bytes.Buffer
	if err := r.CopyCompleted(ctx, id, &actual); err != nil || !bytes.Equal(actual.Bytes(), data) {
		t.Fatalf("queued upload failed integrity verification: %v", err)
	}
}

func TestQueuedUploadCancellationReleasesSession(t *testing.T) {
	r, s, gate := queuedUploadFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var ticket BatchTicket
	done := make(chan error, 1)
	go func() {
		done <- s.SendBatch(ctx, []Source{{Reader: bytes.NewReader([]byte("queued")), Name: "cancel.bin", Size: 6}}, &ticket, func(BatchTicket) error { return nil }, nil)
	}()
	syncUntil(t, func() bool { return len(r.List()) == 1 })
	id := r.List()[0].ID
	if err := r.Decide(id, true); err != nil {
		t.Fatal(err)
	}
	syncUntil(t, func() bool { return r.find(id).uploading.Load() })
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled queued sender succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queued cancellation did not return promptly")
	}
	syncUntil(t, func() bool { return !r.find(id).uploading.Load() })
	if len(gate) != 1 || r.List()[0].Offset != 0 {
		t.Fatal("cancelled waiter consumed another upload's slot or file bytes")
	}
}

func TestQueuedUploadRecipientPauseAndResume(t *testing.T) {
	r, s, gate := queuedUploadFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var ticket BatchTicket
	done := make(chan error, 1)
	go func() {
		done <- s.SendBatch(ctx, []Source{{Reader: bytes.NewReader([]byte("queued")), Name: "pause.bin", Size: 6}}, &ticket, func(BatchTicket) error { return nil }, nil)
	}()
	syncUntil(t, func() bool { return len(r.List()) == 1 })
	id := r.List()[0].ID
	if err := r.Decide(id, true); err != nil {
		t.Fatal(err)
	}
	syncUntil(t, func() bool { return r.find(id).uploading.Load() })
	if err := r.SetPaused(id, true); err != nil {
		t.Fatal(err)
	}
	syncUntil(t, func() bool { return !r.find(id).uploading.Load() })
	if r.List()[0].State != "paused" || r.List()[0].Offset != 0 || len(gate) != 1 {
		t.Fatal("recipient pause failed while queued")
	}
	if err := r.SetPaused(id, false); err != nil {
		t.Fatal(err)
	}
	<-gate
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("same queued transfer did not resume")
	}
	if got := r.List()[0]; got.ID != id || got.State != "completed" {
		t.Fatal("resume replaced the queued transfer")
	}
}
