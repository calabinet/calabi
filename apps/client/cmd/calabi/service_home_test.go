package main

import "testing"

// systemd starts a unit with a nearly empty environment and no HOME; launchd is
// no better. The client resolves its credentials through XDG_CONFIG_HOME/HOME,
// so without one the installed service cannot read the file `calabi login` just
// wrote — it fails with "$HOME is not defined" and enrols with no fingerprint.
//
// Windows is excluded because the SCM has its own profile and the legacy path
// pins the data dir next to the exe instead.
func TestApplyServiceHome(t *testing.T) {
	cases := []struct {
		name string
		goos string
		env  map[string]string
		home string
		want string
	}{
		{"linux gets one", "linux", map[string]string{}, "/root", "/root"},
		{"macos gets one", "darwin", map[string]string{}, "/Users/me", "/Users/me"},
		{"windows does not", "windows", map[string]string{}, `C:\Users\me`, ""},

		// An existing value came from the install shell through the passthrough:
		// a deliberate choice, not ours to overwrite.
		{"an explicit HOME wins", "linux", map[string]string{"HOME": "/srv/calabi"}, "/root", "/srv/calabi"},
		// Nothing to bake is not an error — just nothing to do.
		{"no home to resolve", "linux", map[string]string{}, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			applyServiceHome(c.env, c.goos, c.home)
			if got := c.env["HOME"]; got != c.want {
				t.Fatalf("HOME = %q, want %q", got, c.want)
			}
		})
	}
}
