package main

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/calabi/calabi/apps/client/internal/creds"
)

func TestHasBoolFlag(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{[]string{"--config", "x", "--system"}, true},
		{[]string{"--system=true"}, true},
		{[]string{"-system"}, true},
		{[]string{"--config", "x"}, false},
		{nil, false},
		{[]string{"--system-name"}, false}, // must NOT prefix-match
		{[]string{"--system=false"}, false},
	}
	for _, c := range cases {
		if got := hasBoolFlag(c.args, "system"); got != c.want {
			t.Errorf("hasBoolFlag(%v) = %v, want %v", c.args, got, c.want)
		}
	}
}

// F1: --system bakes the
// marker that makes the run path use SystemDataDir. Independent of the launchd
// domain (which is euid-based, see TestServiceConfig_DarwinDomainByEuid).
func TestServiceConfig_SystemMarker(t *testing.T) {
	if got := serviceConfig([]string{"--system"}, nil).EnvVars["CALABI_SYSTEM_SERVICE"]; got != "1" {
		t.Errorf("--system: CALABI_SYSTEM_SERVICE=%q, want 1", got)
	}
	if _, ok := serviceConfig(nil, nil).EnvVars["CALABI_SYSTEM_SERVICE"]; ok {
		t.Error("no --system must not bake CALABI_SYSTEM_SERVICE")
	}
}

// macOS launchd domain follows euid so install and the later start/stop target
// the same plist path without repeating --system: root → /Library/LaunchDaemons
// (UserService off), a normal user → ~/Library/LaunchAgents (UserService on).
func TestServiceConfig_DarwinDomainByEuid(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin launchd domain logic")
	}
	orig := geteuid
	t.Cleanup(func() { geteuid = orig })

	geteuid = func() int { return 0 } // root
	if v, ok := serviceConfig(nil, nil).Option["UserService"]; ok && v == true {
		t.Error("root must NOT set UserService (want a /Library/LaunchDaemons daemon)")
	}
	geteuid = func() int { return 501 } // normal user
	if serviceConfig(nil, nil).Option["UserService"] != true {
		t.Error("non-root must set UserService (want a ~/Library/LaunchAgents agent)")
	}
}

// Regression for the real-machine bug: launchd/systemd start `calabi daemon`
// directly and never reach the Windows-only runDaemonBody, so the marker must be
// honored on the shared boot chokepoint. applySystemServiceDataDir carries that
// on EVERY platform. With the marker → SystemDataDir; without it → untouched.
func TestApplySystemServiceDataDir_Marker(t *testing.T) {
	t.Setenv("CALABI_SYSTEM_SERVICE", "1")
	creds.SetDataDir("")
	t.Cleanup(func() { creds.SetDataDir("") })

	applySystemServiceDataDir()
	got, err := creds.DataDir()
	if err != nil {
		t.Fatalf("DataDir: %v", err)
	}
	if want := creds.SystemDataDir(); got != want {
		t.Errorf("with marker DataDir=%q, want SystemDataDir %q", got, want)
	}
}

func TestApplySystemServiceDataDir_NoMarker(t *testing.T) {
	t.Setenv("CALABI_SYSTEM_SERVICE", "")
	creds.SetDataDir("keep-me")
	t.Cleanup(func() { creds.SetDataDir("") })

	applySystemServiceDataDir()
	if got, _ := creds.DataDir(); got != "keep-me" {
		t.Errorf("without marker DataDir must be untouched; got %q", got)
	}
}

// Regression for the real-machine "read-only file system" crash: the mesh data
// plane failed to start on the root LaunchDaemon because defaultMeshKeyPath fell
// back to the CWD-relative "calabi-mesh.key" (a root LaunchDaemon has no $HOME,
// so os.UserConfigDir errors), opened against the service's CWD of "/". Under
// the system-service marker the key must resolve to an ABSOLUTE path inside the
// machine-wide SystemDataDir where root can write.
func TestDefaultMeshKeyPath_SystemService(t *testing.T) {
	t.Setenv("CALABI_SYSTEM_SERVICE", "1")
	got := defaultMeshKeyPath()
	if want := filepath.Join(creds.SystemDataDir(), "mesh.key"); got != want {
		t.Errorf("system-service mesh key = %q, want %q", got, want)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("system-service mesh key must be absolute (never CWD-relative), got %q", got)
	}
}
