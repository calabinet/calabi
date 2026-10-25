package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
)

// Exercise the desktop helper's actual shutdown path, not Workspace.Close alone.
func TestDesktopFileAgentShutdownPreservesResume(t *testing.T) {
	for _, side := range []string{"sender", "receiver", "explicit_logout", "receiving_off"} {
		t.Run(side, func(t *testing.T) {
			senderID, err := filetransfer.NewIdentity()
			if err != nil {
				t.Fatal(err)
			}
			receiverID, err := filetransfer.NewIdentity()
			if err != nil {
				t.Fatal(err)
			}
			ip := netip.MustParseAddr("127.0.0.1")
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := uint16(listener.Addr().(*net.TCPAddr).Port)
			senderGrant := filetransfer.Grant{Path: "direct", Peer: filetransfer.Peer{IP: ip, Fingerprint: senderID.Fingerprint}, DeviceKey: "sender", Port: 17401, Receiving: true}
			receiverGrant := filetransfer.Grant{Path: "direct", Peer: filetransfer.Peer{IP: ip, Fingerprint: receiverID.Fingerprint}, DeviceKey: "receiver", Port: port, Receiving: true}
			senderCfg := filetransfer.AgentConfig{Identity: senderID, Directory: t.TempDir(), Scope: "shutdown-sender", LocalIP: ip, Port: 17401, Kbps: 8192, MaxBytes: 4 << 20, Resolve: func(netip.Addr) (filetransfer.Grant, bool) { return receiverGrant, true }, Incoming: func(netip.Addr, uint16) bool { return true }}
			receiverCfg := filetransfer.AgentConfig{Identity: receiverID, Directory: t.TempDir(), Scope: "shutdown-receiver", LocalIP: ip, Port: port, Kbps: 8192, MaxBytes: 4 << 20, Resolve: func(netip.Addr) (filetransfer.Grant, bool) { return senderGrant, true }, Incoming: func(netip.Addr, uint16) bool { return true }}
			sender, err := filetransfer.NewWorkspace(senderCfg)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { sender.Close() }()
			receiver, err := filetransfer.NewWorkspace(receiverCfg)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { receiver.Close() }()
			served, err := receiver.Agent.Serve(listener)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { receiver.Agent.Close(); <-served }()
			if err = receiver.Agent.SetReceiving(true); err != nil {
				t.Fatal(err)
			}
			wait := func(why string, predicate func() bool) {
				t.Helper()
				deadline := time.Now().Add(15 * time.Second)
				for !predicate() {
					if time.Now().After(deadline) {
						t.Fatal(why)
					}
					time.Sleep(time.Millisecond)
				}
			}
			data := bytes.Repeat([]byte("restart-checkpoint"), 100000)
			source, err := sender.Stage(context.Background(), bytes.NewReader(data), "restart.bin", int64(len(data)))
			if err != nil {
				t.Fatal(err)
			}
			job, err := sender.Send(ip, []string{source.ID}, "")
			if err != nil {
				t.Fatal(err)
			}
			wait("offer missing", func() bool { return len(receiver.Agent.List()) == 1 })
			id := receiver.Agent.List()[0].Transfer.ID
			if err = receiver.Agent.Decide([]string{id}, true); err != nil {
				t.Fatal(err)
			}
			wait("no partial body", func() bool { return receiver.Agent.List()[0].Transfer.Offset > 0 })
			if err = receiver.Agent.SetReceivePaused(id, true); err != nil {
				t.Fatal(err)
			}
			before := receiver.Agent.List()[0].Transfer
			if before.Offset <= 0 || before.Offset >= before.Size {
				t.Fatal("missing partial checkpoint")
			}
			wait("sender has not observed receiver pause", func() bool { return sender.Jobs()[0].Progress.Transfer.State == "paused" })
			if side == "explicit_logout" {
				sender.Revoke()
				wait("explicit logout did not cancel receiver", func() bool { return receiver.Agent.List()[0].Transfer.State == "cancelled" })
				return
			}
			if side == "receiving_off" {
				if err = receiver.Agent.SetReceiving(false); err != nil {
					t.Fatal(err)
				}
				if receiver.Agent.List()[0].Transfer.State != "cancelled" {
					t.Fatal("explicit receiving-off retained authorization")
				}
				return
			}
			agentCtx, cancel := context.WithCancel(context.Background())
			closing := sender
			if side == "receiver" {
				closing = receiver
			}
			helper := &desktopFileAgent{ctx: agentCtx, cancel: cancel, w: closing}
			helper.close()
			if side == "sender" {
				got := receiver.Agent.List()[0].Transfer
				if got.State != "paused" || got.ID != id || got.Offset != before.Offset {
					t.Fatalf("shutdown revoked receiver checkpoint: %+v", got)
				}
				sender, err = filetransfer.NewWorkspace(senderCfg)
				if err != nil {
					t.Fatal(err)
				}
				if len(sender.Jobs()) != 1 || sender.Jobs()[0].ID != job || sender.Jobs()[0].State != "paused" {
					t.Fatal("sender task lost on restart")
				}
			} else {
				receiver, err = filetransfer.NewWorkspace(receiverCfg)
				if err != nil {
					t.Fatal(err)
				}
				got := receiver.Agent.List()[0].Transfer
				if got.State != "paused" || got.ID != id || got.Offset != before.Offset {
					t.Fatalf("shutdown revoked local checkpoint: %+v", got)
				}
				if receiver.Agent.Receiving() {
					t.Fatal("restart enabled receiving")
				}
				if err = sender.Pause(job); err != nil {
					t.Fatal(err)
				}
				listener, err = net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
				if err != nil {
					t.Fatal(err)
				}
				oldServed := served
				served, err = receiver.Agent.Serve(listener)
				if err != nil {
					t.Fatal(err)
				}
				<-oldServed
				if err = receiver.Agent.SetReceiving(true); err != nil {
					t.Fatal(err)
				}
			}
			if err = receiver.Agent.SetReceivePaused(id, false); err != nil {
				t.Fatal(err)
			}
			resumed, err := sender.Send(ip, nil, job)
			if err != nil {
				t.Fatal(err)
			}
			if resumed != job {
				t.Fatal("new job created on resume")
			}
			wait("resume did not complete", func() bool { return sender.Jobs()[0].State == "completed" })
			got := receiver.Agent.List()[0].Transfer
			expected := sha256.Sum256(data)
			if got.ID != id || got.Offset != int64(len(data)) || got.SHA256 != hex.EncodeToString(expected[:]) {
				t.Fatalf("resumed transfer changed: %+v", got)
			}
			if err = receiver.Agent.CopyCompleted(context.Background(), id, io.Discard); err != nil {
				t.Fatal(err)
			}
		})
	}
}
