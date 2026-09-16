// console_addr_test.go — what `calabi login` prints about the local console.
//
// The console rolls to the next free port when its own is taken (that is what
// lets several clients share a machine), so the port in the message must be the
// one the daemon WON, not the one it asked for — and when they differ, the user
// deserves to know why :7400 is not theirs.
//
// RUN: go test./apps/client/cmd/calabi/ -run "TestConsoleAddrOf|TestPortRolledNote" -v
package main

import (
	"strings"
	"testing"
)

func TestConsoleAddrOfPrefersWhatTheDaemonPublished(t *testing.T) {
	for _, tc := range []struct{ published, def, want string }{
		{"http://127.0.0.1:7401", "127.0.0.1:7400", "127.0.0.1:7401"},
		{"http://127.0.0.1:7401/", "127.0.0.1:7400", "127.0.0.1:7401"},
		{"  http://127.0.0.1:7402\n", "127.0.0.1:7400", "127.0.0.1:7402"},
		{"https://127.0.0.1:7443", "127.0.0.1:7400", "127.0.0.1:7443"},
		// Nothing published — the daemon is older, or has not written yet.
		// Falling back to the requested address is a guess, but it is the same
		// guess the command made before console.url existed.
		{"", "127.0.0.1:7400", "127.0.0.1:7400"},
		{"   ", "127.0.0.1:7400", "127.0.0.1:7400"},
	} {
		if got := consoleAddrOf(tc.published, tc.def); got != tc.want {
			t.Errorf("consoleAddrOf(%q, %q) = %q, want %q", tc.published, tc.def, got, tc.want)
		}
	}
}

func TestPortRolledNoteOnlyWhenItActuallyRolled(t *testing.T) {
	if n := portRolledNote("127.0.0.1:7400", "127.0.0.1:7400"); n != "" {
		t.Errorf("landed on the requested port but printed %q", n)
	}
	if n := portRolledNote("", "127.0.0.1:7400"); n != "" {
		t.Errorf("no console at all but printed %q", n)
	}
	n := portRolledNote("127.0.0.1:7401", "127.0.0.1:7400")
	if !strings.Contains(n, "127.0.0.1:7400") {
		t.Fatalf("the note must name the port that was TAKEN (the one the user "+
			"will try out of habit), got %q", n)
	}
}
