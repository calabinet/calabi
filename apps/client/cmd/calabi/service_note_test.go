// service_note_test.go — what `calabi login` says about an installed service.
//
// It used to say: "daemon runs as an installed service — start it with
// `calabi daemon start` if it isn't already". That hedge was printed to a user
// who had just watched login establish that nothing was running, and it was a
// hedge only because serviceInstalled() threw away the status it had just
// fetched. We asked the service manager; there is no reason to pass the
// uncertainty on to somebody with less information than us.
//
// RUN: go test./apps/client/cmd/calabi/ -run TestServiceNote -v
package main

import (
	"strings"
	"testing"

	"github.com/kardianos/service"
)

func TestServiceNoteDoesNotHedge(t *testing.T) {
	for _, st := range []service.Status{service.StatusStopped, service.StatusUnknown, service.StatusRunning} {
		note := serviceNote(st)
		if strings.Contains(note, "if it isn't already") {
			t.Errorf("status %v still hedges: %q", st, note)
		}
		if strings.TrimSpace(note) == "" {
			t.Errorf("status %v produced no message", st)
		}
	}
}

// Running and not-running have to read differently — that is the entire point.
// A stopped service also has to name BOTH ways forward: starting it, or running
// a daemon in this shell, because the two serve different credentials (the
// service has its own on Windows and macOS).
func TestServiceNoteTellsRunningFromStopped(t *testing.T) {
	running := serviceNote(service.StatusRunning)
	stopped := serviceNote(service.StatusStopped)
	if running == stopped {
		t.Fatal("a running service and a stopped one get the same sentence")
	}
	if !strings.Contains(running, "running") {
		t.Errorf("running note does not say it is running: %q", running)
	}
	if !strings.Contains(stopped, "NOT running") {
		t.Errorf("stopped note does not say it is not running: %q", stopped)
	}
	for _, want := range []string{"calabi daemon start", "calabi daemon`"} {
		if !strings.Contains(stopped, want) {
			t.Errorf("stopped note does not offer %q: %q", want, stopped)
		}
	}
}
