package mobile

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestJitterWaitPreservesImmediateWakeups(t *testing.T) {
	e := &engine{c: &Core{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}, kick: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	if ok, kicked := e.retryWait(ctx, time.Minute); ok || kicked || time.Since(started) > time.Second {
		t.Fatal("jitter delayed shutdown")
	}
	e.kick <- struct{}{}
	started = time.Now()
	if ok, kicked := e.retryWait(context.Background(), time.Minute); !ok || !kicked || time.Since(started) > time.Second {
		t.Fatal("jitter delayed network-change wakeup")
	}
}
