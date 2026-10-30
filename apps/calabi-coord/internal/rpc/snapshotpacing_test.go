package rpc

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSnapshotPacingInvalidatesImmediately(t *testing.T) {
	deadline := time.Now().Add(time.Hour)
	e := &meshMapState{nextLoad: deadline}
	changed := make(chan struct{})
	close(changed)
	bounded, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := e.waitSnapshotTurn(bounded, changed); !errors.Is(err, errMapSuperseded) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := e.waitSnapshotTurn(ctx, make(chan struct{})); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if !e.nextLoad.Equal(deadline) {
		t.Fatal("notifications extended cooldown")
	}
	// A different organization has no dependency on this stalled load.
	other := &meshMapState{}
	if err := other.waitSnapshotTurn(context.Background(), make(chan struct{})); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotPacingCancellationAndAdmission(t *testing.T) {
	e := &meshMapState{nextLoad: time.Now().Add(time.Hour)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.waitSnapshotTurn(ctx, make(chan struct{})) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("pacing ignored cancellation")
	}
	e.nextLoad = time.Now().Add(20 * time.Millisecond)
	previous := e.nextLoad
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := e.waitSnapshotTurn(ctx, make(chan struct{})); err != nil {
		t.Fatal(err)
	}
	if !e.nextLoad.After(previous) {
		t.Fatal("admission did not reserve spacing")
	}
}
