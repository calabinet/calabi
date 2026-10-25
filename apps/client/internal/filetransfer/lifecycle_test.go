package filetransfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStoppingReceptionReleasesPortAndKeepsWorkspace(t *testing.T) {
	id, _ := NewIdentity()
	ip := netip.MustParseAddr("127.0.0.1")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	a, err := NewAgent(AgentConfig{Identity: id, Directory: t.TempDir(), Scope: "org7", LocalIP: ip, Port: port, Kbps: 512, MaxBytes: 8 << 20, Resolve: func(netip.Addr) (Grant, bool) { return Grant{}, false }, Incoming: func(netip.Addr, uint16) bool { return false }})
	if err != nil {
		l.Close()
		t.Fatal(err)
	}
	defer a.Close()
	done, err := a.Serve(l)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.StopServing(); err != nil {
		t.Fatal(err)
	}
	<-done
	if !a.Alive() || a.Receiving() {
		t.Fatal("stopping listener closed private workspace or retained reception")
	}
	l, err = net.Listen("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("another user cannot bind released port: %v", err)
	}
	done, err = a.Serve(l)
	if err != nil {
		l.Close()
		t.Fatal(err)
	}
	a.StopServing()
	<-done
}

func TestMetadataAndDisableDoNotWaitForStalledUpload(t *testing.T) {
	receiverID, _ := NewIdentity()
	senderID, _ := NewIdentity()
	ip := netip.MustParseAddr("127.0.0.1")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	grant := Grant{Peer: Peer{IP: ip, Fingerprint: senderID.Fingerprint}, DeviceKey: "sender", Port: port}
	agent, err := NewAgent(AgentConfig{Identity: receiverID, Directory: t.TempDir(), Scope: "org7", LocalIP: ip, Port: port, Kbps: 32768, MaxBytes: 8 << 20, Resolve: func(netip.Addr) (Grant, bool) { return grant, true }, Incoming: func(netip.Addr, uint16) bool { return true }})
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	served, err := agent.Serve(listener)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { agent.Close(); <-served }()
	if err := agent.SetReceiving(true); err != nil {
		t.Fatal(err)
	}
	budget, _ := NewPacer(32768)
	s, err := NewBatchSender(senderID, ip, Peer{IP: ip, Fingerprint: receiverID.Fingerprint}, int(port), budget, func() bool { return true }, "sender")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h := sha256.Sum256(bytes.Repeat([]byte("a"), 4096))
	body, _ := json.Marshal(Offer{BatchCount: 1, Batch: randomID(), ClientID: randomID(), Name: "a.txt", Size: 4096, SHA256: hex.EncodeToString(h[:])})
	var offer offerReply
	if err := s.request(context.Background(), s.client, "POST", "/offers", "", bytes.NewReader(body), 0, 0, &offer); err != nil {
		t.Fatal(err)
	}
	if err := agent.Decide([]string{offer.ID}, true); err != nil {
		t.Fatal(err)
	}
	conn, err := tls.Dial("tcp", listener.Addr().String(), senderID.ClientTLS(Peer{IP: ip, Fingerprint: receiverID.Fingerprint}))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = fmt.Fprintf(conn, "PUT /file/v1/transfers/%s HTTP/1.1\r\nHost: test\r\nContent-Length: 4096\r\nX-File-Offset: 0\r\nAuthorization: Bearer %s\r\n\r\nab", offer.ID, offer.Token)
	if err != nil {
		t.Fatal(err)
	}
	r, err := agent.find(offer.ID)
	if err != nil {
		t.Fatal(err)
	}
	session := r.find(offer.ID)
	deadline := time.Now().Add(2 * time.Second)
	for session.mu.TryLock() {
		session.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("upload did not start")
		}
		time.Sleep(time.Millisecond)
	}
	metadata := make(chan []Received, 1)
	go func() { metadata <- agent.List() }()
	select {
	case list := <-metadata:
		if len(list) != 1 || list[0].Transfer.Offset != 0 {
			t.Fatal("metadata acknowledged uncommitted bytes")
		}
	case <-time.After(time.Second):
		t.Fatal("metadata blocked behind network read")
	}
	stopped := make(chan error, 1)
	go func() { stopped <- agent.SetReceiving(false) }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("disable waited for network read")
	}
	if agent.List()[0].Transfer.State != "cancelled" {
		t.Fatal("disable did not persist cancellation")
	}
	if err := agent.SetReceiving(true); err != nil {
		t.Fatal(err)
	}
	var state Transfer
	if err := s.request(context.Background(), s.control, "GET", "/transfers/"+offer.ID, offer.Token, nil, 0, 0, &state); err != nil {
		t.Fatal(err)
	}
	if state.State != "cancelled" {
		t.Fatal("old token resumed after re-enabling")
	}
}

func TestWorkspaceReopensPausedJobAndBoundsStaging(t *testing.T) {
	senderID, _ := NewIdentity()
	receiverID, _ := NewIdentity()
	ip := netip.MustParseAddr("127.0.0.1")
	inbox := t.TempDir()
	r, err := NewReceiver(ReceiverConfig{Peer: Peer{IP: ip, Fingerprint: senderID.Fingerprint}, Directory: inbox, Kbps: 32768, MaxBytes: 4 << 20, Allowed: func() bool { return true }, Durable: true, Scope: "remote"})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	srv, served := r.Serve(listener, receiverID)
	defer func() { srv.Close(); <-served }()
	grant := Grant{Path: "direct", Peer: Peer{IP: ip, Fingerprint: receiverID.Fingerprint}, DeviceKey: "remote", Port: uint16(listener.Addr().(*net.TCPAddr).Port), Receiving: true}
	cfg := AgentConfig{Identity: senderID, Directory: t.TempDir(), Scope: "org7/own", LocalIP: ip, Port: 17401, Kbps: 32768, MaxBytes: 4 << 20, Resolve: func(netip.Addr) (Grant, bool) { return grant, true }, Incoming: func(netip.Addr, uint16) bool { return true }}
	w, err := NewWorkspace(cfg)
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("xyz"), 300000)
	source, err := w.Stage(context.Background(), bytes.NewReader(data), "data.bin", -1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Stage(context.Background(), bytes.NewReader([]byte("changed")), "bad.txt", 1); err == nil {
		t.Fatal("source size change accepted")
	}
	if len(w.Staged()) != 1 {
		t.Fatal("failed staging retained metadata")
	}
	orphan := filepath.Join(cfg.Directory, "source-"+randomID()+".bin")
	if err := os.WriteFile(orphan, []byte("orphan"), 0600); err != nil {
		t.Fatal(err)
	}
	job, err := w.Send(ip, []string{source.ID}, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for len(r.List()) == 0 && ctx.Err() == nil {
		time.Sleep(time.Millisecond)
	}
	if len(r.List()) != 1 {
		t.Fatal("offer not received")
	}
	if err := r.Decide(r.List()[0].ID, true); err != nil {
		t.Fatal(err)
	}
	for ctx.Err() == nil {
		list := w.Jobs()
		if len(list) == 1 && list[0].Progress.Transfer.Offset > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err := w.Pause(job); err != nil {
		t.Fatal(err)
	}
	if got := w.Jobs()[0]; got.State != "paused" || got.Error != "" {
		t.Fatalf("ordinary pause reported an error: %+v", got)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	// Check an older journal as well as preservation of genuine failures.
	journal := filepath.Join(cfg.Directory, "job-"+job+".json")
	for _, stored := range []string{"peer refused transfer", context.Canceled.Error()} {
		b, err := os.ReadFile(journal)
		if err != nil {
			t.Fatal(err)
		}
		var record outgoingRecord
		if err := json.Unmarshal(b, &record); err != nil {
			t.Fatal(err)
		}
		record.Job.Error = stored
		b, err = json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(journal, b, 0600); err != nil {
			t.Fatal(err)
		}
		loaded, err := NewWorkspace(cfg)
		if err != nil {
			t.Fatal(err)
		}
		want := stored
		if stored == context.Canceled.Error() {
			want = ""
		}
		if got := loaded.Jobs()[0].Error; got != want {
			t.Fatalf("restored error = %q, want %q", got, want)
		}
		if err := loaded.Close(); err != nil {
			t.Fatal(err)
		}
	}
	w, err = NewWorkspace(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := os.Stat(orphan); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("orphan staging file not cleaned")
	}
	if len(w.Jobs()) != 1 || w.Jobs()[0].State != "paused" {
		t.Fatal("paused job not recovered")
	}
	if _, err := w.Send(ip, nil, job); err != nil {
		t.Fatal(err)
	}
	for ctx.Err() == nil {
		if w.Jobs()[0].State != "sending" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if got := w.Jobs()[0]; got.State != "completed" {
		t.Fatalf("resume failed: %+v", got)
	}
	var out bytes.Buffer
	if err := r.CopyCompleted(ctx, r.List()[0].ID, &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), data) {
		t.Fatal("reopened source bytes differ")
	}
}

func TestCongestionPauseAndFeedbackRemainCancellable(t *testing.T) {
	p, _ := NewPacer(512)
	p.Observe(10*time.Millisecond, false)
	for n := 0; n < badSamplesBeforePause; n++ {
		p.Observe(500*time.Millisecond, true)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := p.Wait(ctx, 1); err == nil {
		t.Fatal("repeated congestion did not pause")
	}
	p.observeAt(10*time.Millisecond, false, p.pausedUntil.Add(time.Millisecond))
	if err := p.Wait(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	slow, _ := NewPacer(1)
	if err := slow.Wait(context.Background(), paceChunk); err != nil {
		t.Fatal(err)
	}
	ctx2, stop := context.WithCancel(context.Background())
	defer stop()
	done := make(chan error, 1)
	go func() { done <- slow.Wait(ctx2, paceChunk) }()
	feedback := make(chan struct{})
	go func() { slow.Observe(10*time.Millisecond, false); close(feedback) }()
	select {
	case <-feedback:
	case <-time.After(time.Second):
		t.Fatal("low-rate wait blocked congestion feedback")
	}
	stop()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled wait succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("slow pacing did not cancel")
	}
}
