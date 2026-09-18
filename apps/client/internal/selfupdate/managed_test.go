package selfupdate

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

// managedForTest stands in for "this binary was installed by the platform's
// installer". Tests that are about something else — privilege, signatures, the
// policy — hold the install method fixed with it; otherwise their answer would
// depend on whether the test binary happens to sit beside a calabi-desktop.exe,
// and the same test would pass on Linux CI and fail on a Windows laptop.
func managedForTest() bool { return true }

// The matrix that decides whether this platform's update artifact can replace
// the running binary.
func TestInstallerManagedMatrix(t *testing.T) {
	has := func(paths ...string) func(string) bool {
		set := map[string]bool{}
		for _, p := range paths {
			set[p] = true
		}
		return func(p string) bool { return set[p] }
	}
	cases := []struct {
		name   string
		goos   string
		exe    string
		exists func(string) bool
		want   bool
	}{
		// Windows: the desktop installer puts calabi-desktop.exe next to calabi.exe.
		{"windows desktop install", "windows", `C:\Program Files\Calabi\calabi.exe`,
			has(`C:\Program Files\Calabi\calabi-desktop.exe`), true},
		// The case this exists for: scoop + `daemon install --system` was handed
		// the desktop setup.exe.
		{"windows scoop", "windows", `C:\Users\ada\scoop\apps\calabi\1.11.0\calabi.exe`, has(), false},
		{"windows hand-extracted zip", "windows", `C:\tools\calabi\calabi.exe`, has(), false},
		// A desktop exe somewhere ELSE on the machine proves nothing about this one.
		{"windows zip, desktop installed elsewhere", "windows", `C:\tools\calabi\calabi.exe`,
			has(`C:\Program Files\Calabi\calabi-desktop.exe`), false},

		// macOS: exactly the path the.pkg installs and the LaunchDaemon execs.
		{"macos pkg", "darwin", "/Library/Application Support/Calabi/bin/calabi", has(), true},
		{"macos homebrew", "darwin", "/opt/homebrew/Cellar/calabi/1.11.0/bin/calabi", has(), false},
		{"macos tarball", "darwin", "/usr/local/bin/calabi", has(), false},

		// Linux: the tarball is swapped in place — fine unless a package manager
		// owns the tree.
		{"linux install.sh", "linux", "/usr/local/bin/calabi", has(), true},
		{"linux linuxbrew", "linux", "/home/linuxbrew/.linuxbrew/Cellar/calabi/1.11.0/bin/calabi", has(), false},
		{"linux nix", "linux", "/nix/store/abc123-calabi-1.11.0/bin/calabi", has(), false},

		{"unknown os", "freebsd", "/usr/local/bin/calabi", has(), false},
	}
	for _, c := range cases {
		if got := installerManagedFrom(c.goos, c.exe, c.exists); got != c.want {
			t.Errorf("%s: installerManagedFrom(%s, %q) = %v, want %v", c.name, c.goos, c.exe, got, c.want)
		}
	}
}

// Wired into check(): a daemon that was not installed by the platform's
// installer still LEARNS about the new version, reports why it will not
// install it, and never runs the installer.
//
// And the reason wins over not-privileged. For a scoop install the privilege
// advice ("reinstall as a system service") leads nowhere — do it and the
// desktop setup.exe is still the wrong thing to run. Swap the two cases in
// check() and the second half goes red.
func TestForeignInstallChecksButNeverApplies(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	installer := []byte("fake calabi installer payload")
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, installer))
	srv := testServer(t, "1.11.0", installer, sig, "", priv)
	defer srv.Close()

	for _, privileged := range []bool{true, false} {
		u := &Updater{
			ManifestURL:    srv.URL + "/latest.json",
			CurrentVersion: "1.10.0",
			PubKey:         pub,
			DownloadDir:    t.TempDir(),
			Privileged:     privileged,
			Managed:        func() bool { return false }, // e.g. scoop
			Apply: func(context.Context, string) (func() error, error) {
				t.Fatal("the installer must not run for an install it did not make")
				return nil, nil
			},
		}
		st, err := u.Check(context.Background())
		if err != nil {
			t.Fatalf("privileged=%v: Check: %v", privileged, err)
		}
		if !st.Available || !st.HasArtifact {
			t.Errorf("privileged=%v: the new version must still be reported: available=%v has=%v",
				privileged, st.Available, st.HasArtifact)
		}
		if st.CanApply || st.Reason != ReasonManagedElsewhere {
			t.Errorf("privileged=%v: want (cannot apply, %q), got can=%v reason=%q",
				privileged, ReasonManagedElsewhere, st.CanApply, st.Reason)
		}
		if applied, err := u.CheckAndApply(context.Background()); applied || err != nil {
			t.Errorf("privileged=%v: CheckAndApply=(%v,%v), want (false,nil) — a state, not an error",
				privileged, applied, err)
		}
	}
}
