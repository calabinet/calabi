package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// untilCancelled is how every real task behaves: it runs until ctx is
// cancelled, then returns nil.
func untilCancelled(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

// readiness records what superviseTasks reported to /readyz.
type readiness struct {
	mu     sync.Mutex
	states []bool
}

func (r *readiness) set(v bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.states = append(r.states, v)
}

func (r *readiness) endsNotReady() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.states) > 0 && !r.states[len(r.states)-1]
}

// supervise calls superviseTasks as run() does and returns what it logged and
// returned. Were superviseTasks ever to wait for ctx instead of returning,
// the test fails after a few seconds rather than hanging the package.
func supervise(t *testing.T, ctx context.Context, setReady func(bool), tasks ...namedRunner) (string, error) {
	t.Helper()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	done := make(chan error, 1)
	go func() { done <- superviseTasks(ctx, logger, setReady, tasks) }()
	select {
	case err := <-done:
		return logs.String(), err
	case <-time.After(5 * time.Second):
		t.Fatal("superviseTasks did not return")
		return "", nil
	}
}

// A task that returns nil while the edge is meant to be running used to end
// the process with exit status 0 and not one log line. It must fail, at ERROR,
// naming the task — without waiting for a shutdown that nobody asked for.
func TestSuperviseTasksNilReturnBeforeShutdownFails(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var ready readiness

	logs, err := supervise(t, ctx, ready.set,
		namedRunner{"control", untilCancelled},
		namedRunner{"edge-cert-renewer", func(context.Context) error { return nil }},
		namedRunner{"admin", untilCancelled},
	)

	if !errors.Is(err, errExitedEarly) {
		t.Fatalf("err = %v, want errExitedEarly: a nil return before shutdown must make the edge exit non-zero", err)
	}
	if !strings.Contains(err.Error(), "edge-cert-renewer") {
		t.Errorf("err = %q does not name the task", err)
	}
	if want := `level=ERROR msg="task exited before shutdown" task=edge-cert-renewer`; !strings.Contains(logs, want) {
		t.Errorf("logs lack %s\ngot:\n%s", want, logs)
	}
	if !ready.endsNotReady() {
		t.Errorf("readiness %v: /readyz still reports ready after a task died", ready.states)
	}
}

// Shutdown is unchanged: once ctx is cancelled every task returns nil, and
// that is a clean exit.
func TestSuperviseTasksShutdownIsClean(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	var ready readiness

	logs, err := supervise(t, ctx, ready.set,
		namedRunner{"control", untilCancelled},
		namedRunner{"admin", untilCancelled},
	)

	if err != nil {
		t.Fatalf("err = %v, want nil for a requested shutdown", err)
	}
	if !strings.Contains(logs, `msg="shutdown requested"`) || strings.Contains(logs, "level=ERROR") {
		t.Errorf("want a shutdown line and no ERROR; got:\n%s", logs)
	}
	if !ready.endsNotReady() {
		t.Errorf("readiness %v: still ready after shutdown", ready.states)
	}
}

// A signal that lands before superviseTasks reaches its select leaves both the
// cancelled ctx and the tasks' nil results ready, and Go picks either case at
// random. Both must read as the shutdown it is, not as a task quitting early.
func TestSuperviseTasksShutdownRaceIsClean(t *testing.T) {
	for i := range 50 {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		returned := make(chan struct{})
		// setReady(true) runs between launching the tasks and the select:
		// holding it until the task has returned puts that result in the
		// channel before the select looks.
		setReady := func(v bool) {
			if v {
				<-returned
				time.Sleep(time.Millisecond)
			}
		}

		logs, err := supervise(t, ctx, setReady,
			namedRunner{"control", func(ctx context.Context) error {
				defer close(returned)
				return untilCancelled(ctx)
			}},
		)

		if err != nil || strings.Contains(logs, "level=ERROR") {
			t.Fatalf("run %d: err = %v, want a clean shutdown; logged:\n%s", i, err, logs)
		}
	}
}

// A task that fails still ends the process with its own error, prefixed with
// its name.
func TestSuperviseTasksErrorIsReturnedWithTaskName(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	boom := errors.New("listen tcp :8080: bind: address already in use")

	logs, err := supervise(t, ctx, func(bool) {},
		namedRunner{"control", untilCancelled},
		namedRunner{"http", func(context.Context) error { return boom }},
	)

	if !errors.Is(err, boom) || !strings.HasPrefix(err.Error(), "http: ") {
		t.Fatalf("err = %v, want %q prefixed with the task name", err, boom)
	}
	if !strings.Contains(logs, `level=ERROR msg="listener exited"`) {
		t.Errorf("no ERROR line for the failed task; got:\n%s", logs)
	}
}
