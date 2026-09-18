// service_mac_installer_test.go — `calabi daemon …` on a Mac set up by the
// installer has to act on the installer's LaunchDaemon (com.calabi.daemon).
//
// Found 2026-09-16 by reading the service library: it names the launchd job
// after the service name, so start / stop / restart / uninstall only ever
// touched /Library/LaunchDaemons/calabi.plist, which the installer never
// writes — while the desktop app's tray told its users to run them.
//
// launchctl is faked; its output below is the shape `launchctl print` gives on
// macOS. Nothing here has been run against a real Mac yet.
//
// RUN: go test./apps/client/cmd/calabi/ -run 'TestMacInstaller|TestDrivesMacInstaller' -v
package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const launchctlPrintRunning = `system/com.calabi.daemon = {
	active count = 1
	path = /Library/LaunchDaemons/com.calabi.daemon.plist
	type = LaunchDaemon
	state = running

	program = /Library/Application Support/Calabi/bin/calabi
	arguments = {
		/Library/Application Support/Calabi/bin/calabi
		daemon
	}

	pid = 62171
	immediate reason = speculative
}`

const launchctlNotFound = `Could not find service "com.calabi.daemon" in domain for system`

// fakeLaunchctl answers `print` from a script and records every call.
type fakeLaunchctl struct {
	printOut string
	printErr error
	fail     map[string]string // verb → output of a failing call
	calls    []string
}

func (f *fakeLaunchctl) run(args ...string) (string, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	if args[0] == "print" {
		return f.printOut, f.printErr
	}
	if out, ok := f.fail[args[0]]; ok {
		return out, errors.New("exit status 5")
	}
	return "", nil
}

func (f *fakeLaunchctl) called(prefix string) bool {
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func loaded() *fakeLaunchctl { return &fakeLaunchctl{printOut: launchctlPrintRunning} }
func notLoaded() *fakeLaunchctl {
	return &fakeLaunchctl{printOut: launchctlNotFound, printErr: errors.New("exit status 113")}
}

func runMacInstaller(t *testing.T, euid int, lc *fakeLaunchctl, sub string, candidates []string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	m := &macInstallerService{
		euid:       euid,
		launchctl:  lc.run,
		stdout:     &stdout,
		stderr:     &stderr,
		consoleURL: func(time.Time, time.Duration) string { return "" },
		candidates: candidates,
	}
	code := m.run(context.Background(), sub)
	return code, stdout.String(), stderr.String()
}

func TestDrivesMacInstallerServiceOnlyForTheDefaultNameOnAMac(t *testing.T) {
	plist := filepath.Join(t.TempDir(), "com.calabi.daemon.plist")
	if err := os.WriteFile(plist, []byte("<plist/>"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CALABI_SERVICE_NAME", "")
	if !drivesMacInstallerService("darwin", nil, plist) {
		t.Error("default name, installer plist present: not routed to the installer's service")
	}
	if drivesMacInstallerService("darwin", []string{"--service-name", "work"}, plist) {
		t.Error("a --service-name command was routed to the installer's service")
	}
	if drivesMacInstallerService("linux", nil, plist) {
		t.Error("routed to a LaunchDaemon on a non-macOS machine")
	}
	if drivesMacInstallerService("darwin", nil, filepath.Join(t.TempDir(), "absent.plist")) {
		t.Error("routed to the installer's service with no plist on disk")
	}
}

func TestMacInstallerStatusReadsLaunchd(t *testing.T) {
	agent := serviceModeConsole(t, true)
	code, out, _ := runMacInstaller(t, 501, loaded(), "status", []string{agent})
	if code != 0 || !strings.Contains(out, "running (pid 62171)") || !strings.Contains(out, "http://"+agent) {
		t.Errorf("running: exit %d, output:\n%s", code, out)
	}

	code, out, _ = runMacInstaller(t, 501, notLoaded(), "status", nil)
	if code != 0 || !strings.Contains(out, "stopped") || !strings.Contains(out, "not loaded") {
		t.Errorf("not loaded: exit %d, output:\n%s", code, out)
	}

	odd := &fakeLaunchctl{printOut: "Bad request.", printErr: errors.New("exit status 64")}
	code, out, _ = runMacInstaller(t, 501, odd, "status", nil)
	if code != 0 || strings.Contains(out, "stopped") || !strings.Contains(out, "could not report its state: Bad request.") {
		t.Errorf("unexpected launchctl failure read as a state: exit %d, output:\n%s", code, out)
	}
}

// A root job in the system domain: without root, say so before calling launchctl.
func TestMacInstallerControlNeedsRoot(t *testing.T) {
	for _, sub := range []string{"start", "stop", "restart"} {
		lc := loaded()
		code, _, errOut := runMacInstaller(t, 501, lc, sub, nil)
		if code != 1 || !strings.Contains(errOut, "re-run with sudo") {
			t.Errorf("%s as non-root: exit %d, stderr %q", sub, code, errOut)
		}
		if len(lc.calls) != 0 {
			t.Errorf("%s as non-root still ran launchctl: %v", sub, lc.calls)
		}
	}
}

func TestMacInstallerStopBootsOutTheInstallersJob(t *testing.T) {
	lc := loaded()
	code, out, _ := runMacInstaller(t, 0, lc, "stop", nil)
	if code != 0 || !lc.called("bootout system/com.calabi.daemon") || !strings.Contains(out, "stop requested") {
		t.Errorf("exit %d, calls %v, output %q", code, lc.calls, out)
	}

	lc = notLoaded()
	code, out, _ = runMacInstaller(t, 0, lc, "stop", nil)
	if code != 0 || lc.called("bootout") || !strings.Contains(out, "already stopped") {
		t.Errorf("not loaded: exit %d, calls %v, output %q", code, lc.calls, out)
	}

	lc = loaded()
	lc.fail = map[string]string{"bootout": "Boot-out failed: 5: Input/output error"}
	code, _, errOut := runMacInstaller(t, 0, lc, "stop", nil)
	if code != 1 || !strings.Contains(errOut, "Boot-out failed: 5") {
		t.Errorf("failed bootout: exit %d, stderr %q", code, errOut)
	}
}

func TestMacInstallerStartAndRestart(t *testing.T) {
	// Not loaded: enable, then bootstrap from the installer's plist — what
	// postinstall does.
	for _, sub := range []string{"start", "restart"} {
		lc := notLoaded()
		code, _, errOut := runMacInstaller(t, 0, lc, sub, nil)
		if code != 0 || !lc.called("enable system/com.calabi.daemon") ||
			!lc.called("bootstrap system "+macInstallerDaemonPlist) {
			t.Errorf("%s, not loaded: exit %d, calls %v, stderr %q", sub, code, lc.calls, errOut)
		}
	}

	// Loaded: start kickstarts WITHOUT -k (a running daemon is left alone),
	// restart kickstarts WITH -k.
	lc := loaded()
	if code, _, _ := runMacInstaller(t, 0, lc, "start", nil); code != 0 || !lc.called("kickstart system/com.calabi.daemon") || lc.called("kickstart -k") {
		t.Errorf("start, loaded: exit %d, calls %v", code, lc.calls)
	}
	lc = loaded()
	if code, _, _ := runMacInstaller(t, 0, lc, "restart", nil); code != 0 || !lc.called("kickstart -k system/com.calabi.daemon") {
		t.Errorf("restart, loaded: exit %d, calls %v", code, lc.calls)
	}

	lc = notLoaded()
	lc.fail = map[string]string{"bootstrap": "Bootstrap failed: 5: Input/output error"}
	if code, _, errOut := runMacInstaller(t, 0, lc, "start", nil); code != 1 || !strings.Contains(errOut, "Bootstrap failed: 5") {
		t.Errorf("failed bootstrap: exit %d, stderr %q", code, errOut)
	}
}

// install would register a second root daemon over the same data dir;
// uninstall is the installer's to undo. Neither touches launchctl.
func TestMacInstallerRefusesInstallAndUninstall(t *testing.T) {
	lc := loaded()
	code, _, errOut := runMacInstaller(t, 0, lc, "install", nil)
	if code != 1 || !strings.Contains(errOut, "already registered") || !strings.Contains(errOut, "--service-name") {
		t.Errorf("install: exit %d, stderr %q", code, errOut)
	}
	code, _, errOut = runMacInstaller(t, 0, lc, "uninstall", nil)
	if code != 1 || !strings.Contains(errOut, "sudo launchctl bootout system/com.calabi.daemon") ||
		!strings.Contains(errOut, "sudo rm -f "+macInstallerDaemonPlist) {
		t.Errorf("uninstall: exit %d, stderr %q", code, errOut)
	}
	if len(lc.calls) != 0 {
		t.Errorf("install/uninstall ran launchctl: %v", lc.calls)
	}
}
