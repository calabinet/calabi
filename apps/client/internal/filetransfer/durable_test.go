package filetransfer

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

func TestPersistentIdentityAndDeclaration(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if a.Fingerprint != b.Fingerprint {
		t.Fatal("identity changed after restart")
	}
	node := meshproto.NodeKey{1}
	info, err := b.Declaration(node, 17401, false)
	if err != nil {
		t.Fatal(err)
	}
	if pin, err := meshproto.VerifyFileTransfer(node, info, time.Now()); err != nil || pin != a.Fingerprint {
		t.Fatalf("pin=%s err=%v", pin, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "file-identity.json"), []byte("bad"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIdentity(dir); err == nil {
		t.Fatal("corrupt identity silently regenerated")
	}
}

func TestBatchResumeAcrossReceiverAndSenderRestart(t *testing.T) {
	dir := t.TempDir()
	ai, _ := NewIdentity()
	bi, _ := NewIdentity()
	ip := netip.MustParseAddr("127.0.0.1")
	cfg := ReceiverConfig{Peer: Peer{IP: ip, Fingerprint: ai.Fingerprint}, Directory: dir, Kbps: 32768, MaxBytes: 8 << 20, Allowed: func() bool { return true }, Durable: true, Scope: "coord/org7/node1"}
	r, err := NewReceiver(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var receiver atomic.Pointer[Receiver]
	receiver.Store(r)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{TLSConfig: bi.ServerTLS(cfg.Peer), Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { receiver.Load().Handler().ServeHTTP(w, req) })}
	done := make(chan error, 1)
	go func() { done <- srv.ServeTLS(l, "", "") }()
	defer func() { srv.Close(); <-done; receiver.Load().Close() }()
	peer := Peer{IP: ip, Fingerprint: bi.Fingerprint}
	newSender := func() *BatchSender {
		p, _ := NewPacer(32768)
		s, err := NewBatchSender(ai, ip, peer, l.Addr().(*net.TCPAddr).Port, p, func() bool { return true }, "org7/local")
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	data := bytes.Repeat([]byte("abcd"), 200000)
	sources := func() []Source {
		return []Source{{Reader: bytes.NewReader(data), Name: "big.bin", Size: int64(len(data))}, {Reader: bytes.NewReader(nil), Name: "empty.bin", Size: 0}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	acceptDone := make(chan error, 1)
	go func() {
		for ctx.Err() == nil {
			list := receiver.Load().List()
			if len(list) == 2 {
				for _, tr := range list {
					if err := receiver.Load().Decide(tr.ID, true); err != nil {
						acceptDone <- err
						return
					}
				}
				acceptDone <- nil
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		acceptDone <- ctx.Err()
	}()
	var ticket BatchTicket
	var saved []byte
	checkpoint := func(b BatchTicket) error { var err error; saved, err = json.Marshal(b); return err }
	first, stop := context.WithCancel(ctx)
	s := newSender()
	err = s.SendBatch(first, sources(), &ticket, checkpoint, func(p BatchProgress) {
		if p.Transfer.Offset > 0 {
			stop()
		}
	})
	s.Close()
	if err == nil {
		t.Fatal("cancelled attempt completed")
	}
	if err := <-acceptDone; err != nil {
		t.Fatal(err)
	}
	var offset int64
	for _, tr := range r.List() {
		if tr.Name == "big.bin" {
			offset = tr.Offset
			if offset <= 0 || offset >= int64(len(data)) {
				t.Fatalf("not interrupted mid-file: %d", offset)
			}
			f, err := os.OpenFile(filepath.Join(dir, tr.ID+".part"), os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			f.Write([]byte("unacknowledged tail"))
			f.Close()
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = NewReceiver(cfg)
	if err != nil {
		t.Fatal(err)
	}
	receiver.Store(r)
	for _, tr := range r.List() {
		if tr.Name == "big.bin" {
			st, _ := os.Stat(filepath.Join(dir, tr.ID+".part"))
			if tr.Offset != offset || st.Size() != offset {
				t.Fatal("recovery acknowledged an uncommitted tail")
			}
		}
	}
	if err := json.Unmarshal(saved, &ticket); err != nil {
		t.Fatal(err)
	}
	s = newSender()
	defer s.Close()
	if err := s.SendBatch(ctx, sources(), &ticket, checkpoint, nil); err != nil {
		t.Fatal(err)
	}
	if len(r.List()) != 2 {
		t.Fatal("resume created duplicate files")
	}
	for _, tr := range r.List() {
		if tr.State != "completed" {
			t.Fatalf("not completed: %+v", tr)
		}
		var out bytes.Buffer
		if err := r.CopyCompleted(ctx, tr.ID, &out); err != nil {
			t.Fatal(err)
		}
		if tr.Name == "big.bin" && !bytes.Equal(out.Bytes(), data) {
			t.Fatal("resumed bytes differ")
		}
	}
	// Re-running after losing all completion responses returns the same receipts.
	if err := s.SendBatch(ctx, sources(), &ticket, checkpoint, nil); err != nil {
		t.Fatal(err)
	}
	changed := sources()
	changed[0].Reader = bytes.NewReader(bytes.Repeat([]byte("z"), len(data)))
	if err := s.SendBatch(ctx, changed, &ticket, checkpoint, nil); err == nil {
		t.Fatal("changed source resumed")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.Scope = "another-org"
	if other, err := NewReceiver(cfg); err == nil {
		other.Close()
		t.Fatal("foreign scope recovered")
	}
}

func TestAgentDefaultOffAndSwitchRevokesPending(t *testing.T) {
	ai, _ := NewIdentity()
	bi, _ := NewIdentity()
	ip := netip.MustParseAddr("127.0.0.1")
	grant := Grant{Peer: Peer{IP: ip, Fingerprint: bi.Fingerprint}, DeviceKey: meshproto.NodeKey{2}.String(), Port: 17401, Receiving: true}
	a, err := NewAgent(AgentConfig{Identity: ai, Directory: t.TempDir(), Scope: "org7", LocalIP: ip, Port: 17401, Kbps: 32768, MaxBytes: 10, Resolve: func(netip.Addr) (Grant, bool) { return grant, true }, Incoming: func(netip.Addr, uint16) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if a.Receiving() {
		t.Fatal("new agent receiving by default")
	}
	r, err := a.receiver(grant, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.SetReceiving(true); err != nil {
		t.Fatal(err)
	}
	// Create a waiting offer directly through the authenticated peer handler.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	srv, done := r.receiver.Serve(l, ai)
	defer func() { srv.Close(); <-done }()
	p, _ := NewPacer(32768)
	s, _ := NewBatchSender(bi, ip, Peer{IP: ip, Fingerprint: ai.Fingerprint}, l.Addr().(*net.TCPAddr).Port, p, func() bool { return true }, "peer-scope")
	defer s.Close()
	var ticket BatchTicket
	sendDone := make(chan error, 1)
	go func() {
		sendDone <- s.SendBatch(ctx, []Source{{Reader: bytes.NewReader([]byte("a")), Name: "a.txt", Size: 1}}, &ticket, func(BatchTicket) error { return nil }, nil)
	}()
	for len(a.List()) == 0 && ctx.Err() == nil {
		time.Sleep(time.Millisecond)
	}
	if len(a.List()) != 1 {
		t.Fatal("no waiting offer")
	}
	if err := a.SetReceiving(false); err != nil {
		t.Fatal(err)
	}
	if a.List()[0].Transfer.State != "cancelled" {
		t.Fatal("switch did not revoke pending transfer")
	}
	cancel()
	<-sendDone
}
