//go:build windows || darwin || linux

package main

import (
	"context"
	"errors"
	"github.com/calabinet/calabi/apps/client/internal/filecontrol"
	"sync/atomic"
	"testing"
	"time"
)

func TestInboundMetadataRefreshesStaleSnapshot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var offline atomic.Bool
	ctl := &filecontrol.Control{Source: filecontrol.Source{View: func() (filecontrol.Snapshot, error) {
		if offline.Load() {
			return filecontrol.Snapshot{}, errors.New("offline")
		}
		return filecontrol.Snapshot{Ready: true, Scope: "new", ReceiveEpoch: 4}, nil
	}}}
	console := "http://127.0.0.1:17466"
	done, e := filecontrol.Serve(ctx, ctl, console)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { cancel(); <-done }()
	d := desktopFileAgent{ctx: ctx, console: console, view: filecontrol.Snapshot{Ready: true, Scope: "old", OwnsLease: true}, updated: time.Now().Add(-3 * time.Second)}
	got, e := d.inboundMetadata()
	if e != nil || got.Scope != "new" || got.OwnsLease || got.ReceiveEpoch != 4 {
		t.Fatalf("fresh decision: %+v %v", got, e)
	}
	offline.Store(true)
	got, e = d.inboundMetadata()
	if e == nil || got.Ready || got.OwnsLease {
		t.Fatal("accepted stale authorization")
	}
}
