package wake

import (
	"context"
	"testing"
	"time"
)

func TestWoke(t *testing.T) {
	tests := []struct {
		name       string
		mono, wall time.Duration
		want       bool
	}{
		{"an ordinary tick", CheckInterval, CheckInterval, false},
		{"a busy machine, not a sleeping one", 20 * time.Second, 20 * time.Second, false},
		{"monotonic stopped across the suspend", CheckInterval, 20 * time.Minute, true},
		{"monotonic kept running through it", 20 * time.Minute, CheckInterval, true},
		{"both saw it", time.Hour, time.Hour, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Woke(tt.mono, tt.wall); got != tt.want {
				t.Fatalf("Woke(%s, %s) = %v, want %v", tt.mono, tt.wall, got, tt.want)
			}
		})
	}
}

// Loop must stop when its context does. A detector that outlives the session it
// was rebuilding for keeps re-dialing on behalf of nobody.
func TestLoopStopsWithItsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Loop(ctx, func(time.Duration) {}); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Loop did not return after its context was cancelled")
	}
}
