package filetransfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCancellationRetriesAndSurvivesWorkspaceRestart(t *testing.T) {
	for _, scenario := range []struct {
		name            string
		restart, forget bool
	}{
		{"temporary_delete_failure", false, false}, {"offline_and_restart", true, false},
		{"removed_while_pending", false, true}, {"removed_and_restart", true, true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			restart, forget := scenario.restart, scenario.forget
			currentJob := func(w *Workspace, id string) Job {
				w.mu.Lock()
				defer w.mu.Unlock()
				if j := w.jobs[id]; j != nil {
					return j.record.Job
				}
				return Job{State: "cancelled"}
			}
			a, _ := NewIdentity()
			b, _ := NewIdentity()
			ip := netip.MustParseAddr("127.0.0.1")
			r, err := NewReceiver(ReceiverConfig{Peer: Peer{IP: ip, Fingerprint: a.Fingerprint}, Directory: t.TempDir(), Kbps: 512, MaxBytes: 2 << 20, Allowed: func() bool { return true }, Durable: true, Scope: "remote"})
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			var blocked, offline, unauthorized atomic.Bool
			blocked.Store(true)
			var attempts atomic.Int32
			handler := r.Handler()
			srv := &http.Server{TLSConfig: b.ServerTLS(Peer{IP: ip, Fingerprint: a.Fingerprint}), Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method == "DELETE" {
					attempts.Add(1)
					if blocked.Load() {
						w.WriteHeader(503)
						return
					}
				}
				handler.ServeHTTP(w, req)
			})}
			served := make(chan error, 1)
			go func() { served <- srv.ServeTLS(l, "", "") }()
			defer func() { srv.Close(); <-served }()
			grant := Grant{Path: "direct", Peer: Peer{IP: ip, Fingerprint: b.Fingerprint}, DeviceKey: "remote", Port: uint16(l.Addr().(*net.TCPAddr).Port), Receiving: true}
			cfg := AgentConfig{Identity: a, Directory: t.TempDir(), Scope: "local", LocalIP: ip, Port: 17401, Kbps: 512, MaxBytes: 2 << 20, Authority: func() bool { return !unauthorized.Load() }, Resolve: func(netip.Addr) (Grant, bool) { return grant, !offline.Load() }, Incoming: func(netip.Addr, uint16) bool { return true }}
			w, err := NewWorkspace(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { w.Close() }()
			source, err := w.Stage(context.Background(), bytes.NewReader(bytes.Repeat([]byte("x"), 1<<20)), "cancel.bin", 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			job, err := w.Send(ip, []string{source.ID}, "")
			if err != nil {
				t.Fatal(err)
			}
			await := func(why string, predicate func() bool) {
				t.Helper()
				deadline := time.Now().Add(6 * time.Second)
				for !predicate() {
					if time.Now().After(deadline) {
						t.Fatal(why)
					}
					time.Sleep(time.Millisecond)
				}
			}
			await("no offer", func() bool { return len(r.List()) == 1 })
			tr := r.List()[0]
			if err := r.Decide(tr.ID, true); err != nil {
				t.Fatal(err)
			}
			await("no partial data", func() bool { return r.List()[0].Offset > 0 })
			if err := w.Cancel(job); err != nil {
				t.Fatal(err)
			}
			await("cancel request never attempted", func() bool { return attempts.Load() > 0 })
			if !w.HasPendingCancellation() {
				t.Fatal("pending cancellation not published as active control work")
			}
			if got := w.Jobs()[0]; got.State != "cancelled" || !got.CancelPending {
				t.Fatalf("lost cancellation intent: %+v", got)
			}
			if forget {
				unauthorized.Store(true)
				await("authorization loss was not observed", func() bool { return strings.Contains(currentJob(w, job).Error, "no longer authorized") })
				if err := w.ForgetJob(job); err != nil {
					t.Fatal(err)
				}
				if len(w.Jobs()) != 0 {
					t.Fatal("removed history is still visible")
				}
				if err := w.ForgetSource(source.ID); err != nil {
					t.Fatal("hidden cancellation retains source", err)
				}
				w.mu.Lock()
				count := w.visibleJobs()
				w.mu.Unlock()
				if count != 0 {
					t.Fatal("hidden cancellation occupies a task slot")
				}
				if !w.HasPendingCancellation() {
					t.Fatal("hidden cancellation lost control-session requirement")
				}
			}
			if restart {
				offline.Store(true)
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
				// Simulate an older client journal that only says cancelled.
				root, err := os.OpenRoot(cfg.Directory)
				if err != nil {
					t.Fatal(err)
				}
				var legacy outgoingRecord
				if err := readRecord(root, "job-"+job+".json", &legacy); err != nil {
					t.Fatal(err)
				}
				legacy.Job.CancelPending = false
				legacy.Withdrawn = false
				if err := writeRecord(root, "job-"+job+".json", legacy); err != nil {
					t.Fatal(err)
				}
				root.Close()
				w, err = NewWorkspace(cfg)
				if err != nil {
					t.Fatal(err)
				}
				if !currentJob(w, job).CancelPending {
					t.Fatal("restart lost cancellation intent")
				}
			}
			blocked.Store(false)
			offline.Store(false)
			unauthorized.Store(false)
			await("peer never confirmed cancellation", func() bool { return !currentJob(w, job).CancelPending })
			if got := r.List()[0]; got.State != "cancelled" || got.RateBps != 0 {
				t.Fatalf("receiver still active: %+v", got)
			}
			if _, err := r.root.Stat(tr.ID + ".part"); !os.IsNotExist(err) {
				t.Fatal("cancelled partial file retained", err)
			}
			if w.HasPendingCancellation() {
				t.Fatal("acknowledged cancellation retains control-session requirement")
			}
			if err := currentJob(w, job).Error; err != "" {
				t.Fatal("successful retry retained error", err)
			}
			w.mu.Lock()
			var saved outgoingRecord
			err = readRecord(w.root, "job-"+job+".json", &saved)
			w.mu.Unlock()
			if forget {
				if !os.IsNotExist(err) {
					t.Fatal("removed history journal retained", err)
				}
				if len(w.Jobs()) != 0 {
					t.Fatal("removed history reappeared")
				}
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
				w, err = NewWorkspace(cfg)
				if err != nil {
					t.Fatal(err)
				}
				if len(w.Jobs()) != 0 {
					t.Fatal("removed history reappeared after acknowledgment and restart")
				}
			} else if err != nil || !saved.Withdrawn || saved.Job.CancelPending {
				t.Fatal("peer acknowledgment was not durable", err)
			}
		})
	}
}

func TestCancelRecoversLostOfferReplyAndRetainsCompletedFile(t *testing.T) {
	a, _ := NewIdentity()
	b, _ := NewIdentity()
	ip := netip.MustParseAddr("127.0.0.1")
	r, err := NewReceiver(ReceiverConfig{Peer: Peer{IP: ip, Fingerprint: a.Fingerprint}, Directory: t.TempDir(), Kbps: 512, MaxBytes: 2 << 20, Allowed: func() bool { return true }, Durable: true, Scope: "remote"})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, done := r.Serve(l, b)
	defer func() { srv.Close(); <-done }()
	pacer, _ := NewPacer(512)
	s, err := NewBatchSender(a, ip, Peer{IP: ip, Fingerprint: b.Fingerprint}, l.Addr().(*net.TCPAddr).Port, pacer, func() bool { return true }, "local")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h := sha256.Sum256(nil)
	offer := Offer{BatchCount: 1, Batch: randomID(), ClientID: randomID(), Name: "empty.bin", SHA256: hex.EncodeToString(h[:])}
	body, _ := json.Marshal(offer)
	var reply offerReply
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.request(ctx, s.control, "POST", "/offers", "", bytes.NewReader(body), 0, 0, &reply); err != nil {
		t.Fatal(err)
	}
	ticket := BatchTicket{ID: offer.Batch, Scope: s.scope, Peer: s.peer, Files: []FileTicket{{Offer: offer}}}
	if err := s.CancelBatch(ctx, ticket); err != nil {
		t.Fatal(err)
	}
	if len(r.List()) != 1 || r.List()[0].State != "cancelled" {
		t.Fatal("lost offer reply left orphan request")
	}
	// A completed file wins a race with cancellation and must remain exportable.
	offer.Batch = randomID()
	offer.ClientID = randomID()
	body, _ = json.Marshal(offer)
	if err := s.request(ctx, s.control, "POST", "/offers", "", bytes.NewReader(body), 0, 0, &reply); err != nil {
		t.Fatal(err)
	}
	if err := r.Decide(reply.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := s.request(ctx, s.control, "POST", "/transfers/"+reply.ID+"/commit", reply.Token, nil, 0, 0, nil); err != nil {
		t.Fatal(err)
	}
	ticket = BatchTicket{ID: offer.Batch, Scope: s.scope, Peer: s.peer, Files: []FileTicket{{Offer: offer, ID: reply.ID, Token: reply.Token}}}
	if err := s.CancelBatch(ctx, ticket); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := r.CopyCompleted(ctx, reply.ID, &out); err != nil {
		t.Fatal("completed file was revoked", err)
	}
}
