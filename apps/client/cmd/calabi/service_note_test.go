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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

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

// --- an installed service keeps its own credential -------------------------
//
// Reproduced 2026-09-16 on a Windows desktop install, from a non-admin shell:
// `calabi login` took the service manager's Access is denied for "not
// installed" and started a second daemon on :7401 — a second device for the
// same machine, joining the meshnet as the person who typed the login — while
// the desktop app's service went on under its own sign-in.

func TestServiceNoteNeverSaysTheLoginWasHandedOver(t *testing.T) {
	for _, st := range []service.Status{service.StatusRunning, service.StatusUnknown} {
		note := serviceNote(st)
		if strings.Contains(note, "that is this machine's daemon") {
			t.Errorf("status %v reads as if the service took this login: %q", st, note)
		}
		if !strings.Contains(note, "its own sign-in") {
			t.Errorf("status %v does not say the service keeps its own sign-in: %q", st, note)
		}
	}
}

func TestClassifyServiceStatusCountsARefusalAsInstalled(t *testing.T) {
	type tc struct {
		name          string
		st            service.Status
		err           error
		wantInstalled bool
		wantSt        service.Status
	}
	cases := []tc{
		{"answered", service.StatusRunning, nil, true, service.StatusRunning},
		{"not installed", service.StatusUnknown, service.ErrNotInstalled, false, service.StatusUnknown},
		{"not allowed to ask", service.StatusUnknown, fmt.Errorf("open service: %w", os.ErrPermission), true, service.StatusUnknown},
		// No usable service manager at all keeps the transient-daemon path.
		{"anything else", service.StatusUnknown, errors.New("systemctl: not found"), false, service.StatusUnknown},
	}
	if runtime.GOOS == "windows" {
		// What kardianos actually returns: the raw errno from OpenService.
		cases = append(cases, tc{"ERROR_ACCESS_DENIED", service.StatusUnknown, syscall.Errno(5), true, service.StatusUnknown})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st, installed := classifyServiceStatus(c.st, c.err)
			if installed != c.wantInstalled || st != c.wantSt {
				t.Fatalf("classifyServiceStatus(%v, %v) = (%v, %v), want (%v, %v)",
					c.st, c.err, st, installed, c.wantSt, c.wantInstalled)
			}
		})
	}
}

func TestMacInstallerServicePresent(t *testing.T) {
	plist := filepath.Join(t.TempDir(), "com.calabi.daemon.plist")
	if macInstallerServicePresent("darwin", plist) {
		t.Fatal("reported present with no plist on disk")
	}
	if err := os.WriteFile(plist, []byte("<plist/>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !macInstallerServicePresent("darwin", plist) {
		t.Fatal("the installer's LaunchDaemon plist is on disk but was not recognised")
	}
	if macInstallerServicePresent("linux", plist) {
		t.Fatal("a LaunchDaemon path counted on a non-macOS machine")
	}
}

func TestInstalledServiceNote(t *testing.T) {
	signedIn := []otherClient{{Addr: "127.0.0.1:7400"}}
	note := installedServiceNote(service.StatusUnknown, signedIn, true)
	for _, want := range []string{
		"http://127.0.0.1:7400 keeps its own sign-in",
		"this login is for commands run in this shell",
		"not starting a second daemon",
		"`calabi daemon`",
	} {
		if !strings.Contains(note, want) {
			t.Errorf("note lacks %q:\n%s", want, note)
		}
	}

	agent := installedServiceNote(service.StatusRunning, []otherClient{{Addr: "127.0.0.1:7400", Agent: true}}, false)
	if !strings.Contains(agent, "runs on its own API key") {
		t.Errorf("agent service not described as running on its key:\n%s", agent)
	}
	if strings.Contains(agent, "not starting") {
		t.Errorf("--no-start-daemon login told it was not starting a daemon it never asked for:\n%s", agent)
	}

	// A stopped service with nothing answering: serviceNote already names both
	// ways forward, and there is nothing running for a daemon to be "second" to.
	if got, want := installedServiceNote(service.StatusStopped, nil, true), serviceNote(service.StatusStopped); got != want {
		t.Errorf("stopped service note = %q, want exactly %q", got, want)
	}
}

// `calabi join` on a computer with a calabi service: the service is another
// client, with its own data. join used to print login's note, which says to
// start a stopped service — and a tester did, starting the computer's platform
// client instead of anything on the server just joined.
func TestJoinServiceNoteNeverSendsYouToTheService(t *testing.T) {
	for _, st := range []service.Status{service.StatusStopped, service.StatusRunning, service.StatusUnknown} {
		note := joinServiceNote(st)
		if strings.Contains(note, "daemon start") {
			t.Errorf("status %v: the join note offers to start the service: %q", st, note)
		}
		for _, want := range []string{"separate client", "does not reach it", "calabi daemon", "Settings → Connect"} {
			if !strings.Contains(note, want) {
				t.Errorf("status %v: the join note does not say %q: %q", st, want, note)
			}
		}
	}
}

// After `calabi daemon start` the console address is looked for where a service
// keeps its data — the machine-wide dir included — and never reported as being
// next to THIS copy of calabi, which need not be the service's.
func TestDaemonStartLooksWhereTheServiceKeepsItsData(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the machine-wide dir is fixed outside Windows")
	}
	programData := t.TempDir()
	t.Setenv("ProgramData", programData)
	sys := filepath.Join(programData, "Calabi")
	if err := os.MkdirAll(sys, 0o700); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := os.WriteFile(filepath.Join(sys, consoleURLFile), []byte("http://127.0.0.1:7400\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() { printConsoleHint(start) })
	if !strings.Contains(out, "console: http://127.0.0.1:7400") {
		t.Fatalf("printConsoleHint = %q, want the address the service wrote in the machine-wide dir", out)
	}

	if err := os.Remove(filepath.Join(sys, consoleURLFile)); err != nil {
		t.Fatal(err)
	}
	out = captureStdout(t, func() { printConsoleHint(time.Now()) })
	if dir := exeDir(); dir != "" && strings.Contains(out, dir) {
		t.Fatalf("printConsoleHint = %q, names this copy's directory %s", out, dir)
	}
}
