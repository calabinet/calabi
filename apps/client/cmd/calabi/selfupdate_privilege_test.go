package main

import "testing"

// The matrix that decides whether a daemon may install an update on itself.
//
// This used to be one env check (`CALABI_SYSTEM_SERVICE == "1"`), which describes
// privilege only on macOS. On Linux and Windows a plain `daemon install` already
// produces a root systemd unit / LocalSystem service, so the marker was missing
// on precisely the machines that COULD update themselves — and the console told
// a uid-0 process it lacked privilege.
func TestPrivilegedForUpdatesMatrix(t *testing.T) {
	cases := []struct {
		name        string
		marker      string
		interactive bool
		goos        string
		euid        int
		want        bool
	}{
		// The marker is still the cheapest true answer: the desktop installers set it.
		{"marker wins regardless", "1", true, "linux", 1000, true},

		// The case this change exists for.
		{"linux systemd as root", "", false, "linux", 0, true},
		{"windows service", "", false, "windows", -1, true},

		// Started from a shell. Refused even as root: there is no unit for us to
		// restart, and restarting "calabi" from here would either fail or restart
		// somebody else's service while this process keeps the old binary.
		{"foreground sudo", "", true, "linux", 0, false},
		{"foreground user", "", true, "linux", 1000, false},
		{"foreground windows", "", true, "windows", -1, false},

		// A per-user unit cannot replace a root-owned binary.
		{"linux user unit", "", false, "linux", 1000, false},
		{"macos LaunchAgent", "", false, "darwin", 501, false},
		{"macos LaunchDaemon", "", false, "darwin", 0, true},
	}
	for _, c := range cases {
		if got := privilegedForUpdatesFrom(c.marker, c.interactive, c.goos, c.euid); got != c.want {
			t.Errorf("%s: privilegedForUpdatesFrom(%q, interactive=%v, %s, euid=%d) = %v, want %v",
				c.name, c.marker, c.interactive, c.goos, c.euid, got, c.want)
		}
	}
}

// Windows reports euid -1, so any rule phrased as a uid comparison is false
// there forever. Pinned separately because the bug would look like "Windows
// services just never self-update" and nothing would say why.
func TestWindowsServiceIsNotDecidedByUID(t *testing.T) {
	if !privilegedForUpdatesFrom("", false, "windows", -1) {
		t.Error("a Windows service was judged unprivileged — os.Geteuid() is -1 there, not 0")
	}
}
