package filetransfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func stateSyncPair(t *testing.T) (*Workspace, *Receiver, string) {
	t.Helper()
	senderID, _ := NewIdentity()
	receiverID, _ := NewIdentity()
	ip := netip.MustParseAddr("127.0.0.1")
	inbox := t.TempDir()
	r, err := NewReceiver(ReceiverConfig{Peer: Peer{IP: ip, Fingerprint: senderID.Fingerprint}, Directory: inbox, Kbps: 32768, MaxBytes: 16 << 20, Allowed: func() bool { return true }, Durable: true, Scope: "remote"})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, served := r.Serve(listener, receiverID)
	grant := Grant{Path: "direct", Peer: Peer{IP: ip, Fingerprint: receiverID.Fingerprint}, DeviceKey: "remote", Port: uint16(listener.Addr().(*net.TCPAddr).Port), Receiving: true}
	w, err := NewWorkspace(AgentConfig{Identity: senderID, Directory: t.TempDir(), Scope: "sync", LocalIP: ip, Port: 17401, Kbps: 32768, MaxBytes: 16 << 20, Resolve: func(netip.Addr) (Grant, bool) { return grant, true }, Incoming: func(netip.Addr, uint16) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close(); srv.Close(); <-served; r.Close() })
	return w, r, inbox
}

func syncUntil(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("state did not converge")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestReceiverPauseContinuesSameTicketAndVerifiedBytes(t *testing.T) {
	w, r, inbox := stateSyncPair(t)
	data := bytes.Repeat([]byte("pause-resume"), 100000)
	source, err := w.Stage(context.Background(), bytes.NewReader(data), "pause.bin", int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Send(netip.MustParseAddr("127.0.0.1"), []string{source.ID}, ""); err != nil {
		t.Fatal(err)
	}
	syncUntil(t, func() bool { return len(r.List()) == 1 })
	id := r.List()[0].ID
	if err = r.Decide(id, true); err != nil {
		t.Fatal(err)
	}
	syncUntil(t, func() bool { return r.List()[0].Offset > 0 })
	if err = r.SetPaused(id, true); err != nil {
		t.Fatal(err)
	}
	paused := r.List()[0]
	if paused.State != "paused" || paused.RateBps != 0 {
		t.Fatalf("not paused: %+v", paused)
	}
	syncUntil(t, func() bool { return w.Jobs()[0].Progress.Transfer.State == "paused" })
	if got := w.Jobs()[0]; got.State != "sending" || got.Error != "" {
		t.Fatalf("peer pause became a local failure: %+v", got)
	}
	time.Sleep(200 * time.Millisecond)
	if r.List()[0].Offset != paused.Offset {
		t.Fatal("paused offset advanced")
	}
	if err = r.SetPaused(id, false); err != nil {
		t.Fatal(err)
	}
	syncUntil(t, func() bool { return w.Jobs()[0].State == "completed" })
	got := r.List()[0]
	if got.ID != id || got.Offset != int64(len(data)) || got.State != "completed" {
		t.Fatalf("new or incomplete transfer: %+v", got)
	}
	body, err := os.ReadFile(filepath.Join(inbox, got.StoredName))
	if err != nil || !bytes.Equal(body, data) {
		t.Fatal("resumed bytes changed", err)
	}
}

func TestRecipientStopIsTerminalOnActiveAndPausedSender(t *testing.T) {
	for _, mode := range []string{"reject", "cancel", "cancel-paused"} {
		t.Run(mode, func(t *testing.T) {
			w, r, inbox := stateSyncPair(t)
			source, err := w.Stage(context.Background(), bytes.NewReader(bytes.Repeat([]byte("x"), 2<<20)), "stop.bin", 2<<20)
			if err != nil {
				t.Fatal(err)
			}
			job, err := w.Send(netip.MustParseAddr("127.0.0.1"), []string{source.ID}, "")
			if err != nil {
				t.Fatal(err)
			}
			syncUntil(t, func() bool { return len(r.List()) == 1 })
			id := r.List()[0].ID
			want := "receiver_cancelled"
			if mode == "reject" {
				want = "receiver_rejected"
				err = r.Decide(id, false)
			} else {
				if err = r.Decide(id, true); err != nil {
					t.Fatal(err)
				}
				syncUntil(t, func() bool { return r.List()[0].Offset > 0 })
				if mode == "cancel-paused" {
					if err = w.Pause(job); err != nil {
						t.Fatal(err)
					}
				}
				err = r.Cancel(id)
			}
			if err != nil {
				t.Fatal(err)
			}
			syncUntil(t, func() bool { j := w.Jobs()[0]; return j.State == "cancelled" && !j.CancelPending })
			if got := w.Jobs()[0]; got.StopReason != want || got.Error != "" {
				t.Fatalf("wrong terminal meaning: %+v", got)
			}
			if _, err = os.Stat(filepath.Join(inbox, id+".part")); !os.IsNotExist(err) {
				t.Fatal("cancelled partial retained", err)
			}
			if _, err = w.Send(netip.MustParseAddr("127.0.0.1"), nil, job); err == nil {
				t.Fatal("cancelled job resumed")
			}
		})
	}
}

func TestRecipientPauseInterruptsStalledBlock(t *testing.T) {
	w, r, inbox := stateSyncPair(t)
	sender, err := w.Agent.Sender(netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	// Create an ordinary offer, then hold its body open without sending bytes.
	source, err := w.Stage(context.Background(), bytes.NewReader(bytes.Repeat([]byte("x"), 1<<20)), "stalled.bin", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	job, err := w.Send(netip.MustParseAddr("127.0.0.1"), []string{source.ID}, "")
	if err != nil {
		t.Fatal(err)
	}
	// The receiver can publish the offer before the sender has persisted its
	// authenticated ticket. The raw upload below needs that checkpoint first.
	syncUntil(t, func() bool {
		if len(r.List()) != 1 {
			return false
		}
		w.mu.Lock()
		defer w.mu.Unlock()
		files := w.jobs[job].record.Ticket.Files
		return len(files) == 1 && validID(files[0].ID) && validID(files[0].Token)
	})
	if err = w.Pause(job); err != nil {
		t.Fatal(err)
	}
	id := r.List()[0].ID
	if err = r.Decide(id, true); err != nil {
		t.Fatal(err)
	}
	w.mu.Lock()
	ticket := w.jobs[job].record.Ticket.Files[0]
	w.mu.Unlock()
	u, _ := url.Parse(sender.base)
	conn, err := tls.Dial("tcp", u.Host, w.Agent.cfg.Identity.ClientTLS(sender.peer))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = fmt.Fprintf(conn, "PUT /file/v1/transfers/%s HTTP/1.1\r\nHost: test\r\nContent-Length: %d\r\nX-File-Offset: 0\r\nAuthorization: Bearer %s\r\n\r\nab", id, paceChunk, ticket.Token); err != nil {
		t.Fatal(err)
	}
	syncUntil(t, func() bool { return r.find(id).uploading.Load() })
	paused := make(chan error, 1)
	go func() { paused <- r.SetPaused(id, true) }()
	select {
	case err = <-paused:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("pause waited for stalled read")
	}
	conn.Close()
	if got := r.List()[0]; got.State != "paused" || got.Offset != 0 {
		t.Fatalf("stalled pause acknowledged unpersisted bytes: %+v", got)
	}
	st, err := os.Stat(filepath.Join(inbox, id+".part"))
	if err != nil || st.Size() != 0 {
		t.Fatal("partial block retained", err)
	}
	w.Close()
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	restored, err := NewReceiver(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if got := restored.List()[0]; got.State != "paused" || got.Offset != 0 || got.ID != id {
		t.Fatalf("paused restart changed state: %+v", got)
	}
	if err = restored.SetPaused(id, false); err != nil {
		t.Fatal(err)
	}
}

func TestLegacySenderDoesNotReceiveNewPauseOrIdleWireStates(t *testing.T) {
	w, r, _ := stateSyncPair(t)
	sender, err := w.Agent.Sender(netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	hash := sha256.Sum256([]byte("abc"))
	offer := Offer{ClientID: randomID(), Batch: randomID(), BatchCount: 1, Name: "old.txt", Size: 3, SHA256: hex.EncodeToString(hash[:])}
	body, _ := json.Marshal(offer)
	// Bypass Sender.request to represent an old client without the opt-in header.
	response, err := sender.client.Post(sender.base+"/offers", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var reply offerReply
	err = json.NewDecoder(response.Body).Decode(&reply)
	response.Body.Close()
	if err != nil || response.StatusCode != 201 {
		t.Fatal("legacy offer failed", err, response.Status)
	}
	if err = r.Decide(reply.ID, true); err != nil {
		t.Fatal(err)
	}
	if err = r.SetPaused(reply.ID, true); err == nil {
		t.Fatal("legacy sender incorrectly opted into receiver pause")
	}
	r.find(reply.ID).lastActivity.Store(time.Now().Add(-6 * time.Second).UnixNano())
	if got := r.List()[0]; got.State != "waiting_sender" || got.RateBps != 0 {
		t.Fatalf("idle UI still claims reception: %+v", got)
	}
	var wire Transfer
	if err = sender.request(context.Background(), sender.control, "GET", "/transfers/"+reply.ID, reply.Token, nil, 0, 0, &wire); err != nil || wire.State != "accepted" {
		t.Fatalf("legacy wire state changed: %+v, %v", wire, err)
	}
	// The same persisted ticket can opt in after upgrading its sender.
	var upgraded offerReply
	if err = sender.request(context.Background(), sender.control, "POST", "/offers", "", bytes.NewReader(body), 0, 0, &upgraded); err != nil {
		t.Fatal(err)
	}
	if upgraded.ID != reply.ID || upgraded.Token != reply.Token || !upgraded.PauseSupported {
		t.Fatal("upgrade replaced a ticket or failed to negotiate pause")
	}
	if err = r.SetPaused(reply.ID, true); err != nil {
		t.Fatal(err)
	}
}
