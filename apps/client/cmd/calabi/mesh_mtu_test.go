package main

import (
	"testing"

	"github.com/calabi/calabi/apps/client/internal/mesh"
)

// The MTU knob had a hole: the YAML `mesh:` block only reaches the LOCAL daemon,
// while every installed machine runs the PLATFORM one, which builds its
// meshConfig in code and never fills MTU in. So the escape hatch existed on the
// one deployment that would never need it. The env var closes that — both kinds
// go through resolveMeshMTU.
func TestResolveMeshMTU(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  string
		cfg  int
		want int
	}{
		{"nothing set means default", "", 0, 0},
		{"config value is used", "", 1300, 1300},
		{"env wins over config", "1200", 1400, 1200},
		{"env alone", "1350", 0, 1350},
		// Both sources are STORED — a unit file, a plist, a YAML block, read long
		// after they were written by a service with nobody watching. An unusable
		// value costs itself, never the whole mesh session.
		{"unusable env falls back to config", "99", 1300, 1300},
		{"unparseable env falls back to config", "wat", 1300, 1300},
		{"unusable config falls back to the default", "", 70000, 0},
		{"too small is refused", "", mesh.MinMTU - 1, 0},
		{"too large is refused", "", mesh.MaxMTU + 1, 0},
		{"the bounds themselves are allowed", "", mesh.MaxMTU, mesh.MaxMTU},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(meshMTUEnv, tc.env)
			if got := resolveMeshMTU(tc.cfg, nil); got != tc.want {
				t.Errorf("resolveMeshMTU(%d) with %s=%q = %d, want %d",
					tc.cfg, meshMTUEnv, tc.env, got, tc.want)
			}
		})
	}
}
