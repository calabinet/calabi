package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
)

// errExitedEarly is how superviseTasks reports a task that returned nil while
// the edge was still meant to be running.
var errExitedEarly = errors.New("exited before shutdown (returned nil)")

// taskExit is what a task's goroutine sends when it returns. The name travels
// with the result because a nil error has nowhere else to carry it.
type taskExit struct {
	name string
	err  error
}

// superviseTasks starts every long-lived task of the process — the listeners,
// the relay, the admin server, the config reloader, the platform's background
// runners — each in its own goroutine, and returns once the process should
// stop. Whichever happens first decides how:
//
//   - ctx is cancelled (SIGINT/SIGTERM): the requested shutdown, nil.
//   - a task returns an error: that error, prefixed with the task's name.
//   - a task returns nil while ctx is still live: errExitedEarly, logged at
//     ERROR with the task's name. No task here is meant to finish on its own —
//     each runs until ctx is cancelled, its "nothing to do on this node"
//     branch included — so this is a bug in that task, and it takes the whole
//     edge down with it. It used to be treated as a clean exit: status 0 and
//     not one log line. That is how a cert renewer with a bare `return nil` on
//     its skip path stopped every platform edge about a second after boot,
//     looking for all the world like an edge that had been asked to stop.
//
// The other tasks are not waited for: run() returns and the process exits.
func superviseTasks(ctx context.Context, logger *slog.Logger, setReady func(bool), tasks []namedRunner) error {
	// One slot per task, so no send ever blocks — not even from a task that
	// returns after this function has.
	exits := make(chan taskExit, len(tasks))
	for _, t := range tasks {
		go func() { exits <- taskExit{name: t.name, err: t.run(ctx)} }()
	}

	// Ready as soon as every task is launched, not when the listeners have
	// bound: nothing signals that yet.
	setReady(true)

	select {
	case <-ctx.Done():
		logger.Info("shutdown requested")
		setReady(false)
		return nil
	case exit := <-exits:
		setReady(false)
		if exit.err != nil {
			err := fmt.Errorf("%s: %w", exit.name, exit.err)
			logger.Error("listener exited", "err", err)
			return err
		}
		// Tasks return nil once ctx is cancelled, so a signal that lands before
		// this select is reached can leave both cases ready, and Go picks
		// either. This is still that shutdown, not a task quitting early.
		if ctx.Err() != nil {
			logger.Info("shutdown requested")
			return nil
		}
		logger.Error("task exited before shutdown", "task", exit.name)
		return fmt.Errorf("%s: %w", exit.name, errExitedEarly)
	}
}
