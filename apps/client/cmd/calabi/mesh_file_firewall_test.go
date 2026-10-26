package main

import "testing"

func TestFileFirewallRejectsUnknownActionAndProgramOverride(t *testing.T) {
	for _, args := range [][]string{nil, {"apply"}, {"install", "--program", "other.exe"}, {"remove", "extra"}} {
		if got := runMeshFiles(append([]string{"firewall"}, args...)); got != 2 {
			t.Fatalf("args %q: got %d, want usage error before any firewall work", args, got)
		}
	}
}
