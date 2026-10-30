package rpc

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestFleetBackgroundCancellationAndPhaseReset(t *testing.T) {
	if os.Getenv("CALABI_FLEET_PG_DSN") == "" || testing.Short() {
		t.Skip("isolated PostgreSQL opt-in")
	}
	t.Setenv("CALABI_FLEET_BACKGROUND_RPS", "400")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := startFleetBackground(t, ctx)
	defer b.stop()
	deadline := time.Now().Add(5 * time.Second)
	for b.snapshot()["completed"].(int) < 20 {
		if time.Now().After(deadline) {
			t.Fatal("background did not make progress")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if b.snapshot()["errors"].(int) != 0 {
		t.Fatal("background query failed")
	}
	cancel()
	done := make(chan struct{})
	go func() { b.stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("background cancellation leaked workers")
	}
	b.reset()
	snap := b.snapshot()
	if snap["completed"].(int) != 0 || snap["errors"].(int) != 0 || snap["missed_arrivals"].(int) != 0 || snap["samples"].(int) != 0 {
		t.Fatalf("previous phase contaminated next: %v", snap)
	}
}
