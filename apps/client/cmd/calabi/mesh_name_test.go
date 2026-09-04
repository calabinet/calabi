package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A mesh name is a MagicDNS label peers resolve, so the label rules are not
// cosmetic: coord's ValidateNodeName rejects anything else, and two machines
// answering to one name is an ambiguous lookup.
func TestMeshNodeLabel(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"my-laptop", "my-laptop"},
		{"DESKTOP-AB12", "desktop-ab12"},
		{"host.example.com", "host-example-com"},
		{"  Spaced Name  ", "spaced-name"},
		{"under_score", "under-score"},
		{"-leading-and-trailing-", "leading-and-trailing"},
		{"weird!!name", "weirdname"},
		{"a..b", "a-b"}, // collapsed, not "a--b" (double dash is legal but ugly)
	} {
		if got := meshNodeLabel(tc.in); got != tc.want {
			t.Errorf("meshNodeLabel(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// An unusable hostname must NOT fall back to a shared constant — that would
// guarantee the very name collision the label exists to avoid.
func TestMeshNodeLabelUnusableIsRandom(t *testing.T) {
	a, b := meshNodeLabel("!!!"), meshNodeLabel("")
	for _, got := range []string{a, b} {
		if !strings.HasPrefix(got, "eq-") || len(got) != len("eq-")+8 {
			t.Fatalf("fallback = %q, want eq-<8 hex>", got)
		}
	}
	if a == b {
		t.Errorf("two fallbacks collided: %q", a)
	}
}

// Over-long hostnames are truncated to one DNS label and must not end in "-".
func TestMeshNodeLabelTruncates(t *testing.T) {
	got := meshNodeLabel(strings.Repeat("x", 70) + "-tail")
	if len(got) != 63 {
		t.Fatalf("len = %d, want 63", len(got))
	}
	got2 := meshNodeLabel(strings.Repeat("y", 62) + "-zzz")
	if strings.HasSuffix(got2, "-") {
		t.Errorf("truncation left a trailing dash: %q", got2)
	}
}

// An explicit --name wins; its absence must never reach the flag's "daemon"
// default, which is a fine CLIENT name and a broken MESH name.
func TestMeshNodeNameFor(t *testing.T) {
	if got := meshNodeNameFor("Office NAS"); got != "office-nas" {
		t.Errorf("explicit name = %q, want office-nas", got)
	}
	// No explicit name: a random label, NOT the hostname — the name is the only
	// identifier that reaches peers, and publishing everyone's hostname to the
	// whole org is a leak that cannot be undone.
	got := meshNodeNameFor("")
	if !strings.HasPrefix(got, "eq-") || len(got) != len("eq-")+8 {
		t.Errorf("default name = %q, want eq-<8 hex>", got)
	}
	if h, err := os.Hostname(); err == nil && h != "" && got == meshNodeLabel(h) {
		t.Errorf("default name leaked the hostname: %q", got)
	}
	// Two MACHINES must not collide — that is the property this label exists for
	// ("daemon.mesh" resolving to whichever host you happen to hit). Two calls on
	// ONE machine returning the same name is now correct and required: the label
	// is persisted so <name>.mesh survives a restart. A machine is a creds file.
	nameOn := func(t *testing.T) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(p, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("CALABI_CONFIG", p)
		return meshNodeNameFor("")
	}
	if nameOn(t) == nameOn(t) {
		t.Error("two machines collided on the default label")
	}
}

// The mesh name is the MagicDNS label peers resolve (<name>.mesh). It used to be
// re-rolled on every daemon start, so a peer that had been reaching
// eq-50b6f778.mesh found nothing the moment that machine restarted — and the
// console showed a device whose name changed on every boot.
func TestMeshNodeNameIsStableAcrossRestarts(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CALABI_CONFIG", p)

	first := meshNodeNameFor("")
	if !strings.HasPrefix(first, "eq-") {
		t.Fatalf("minted name = %q, want an eq- label", first)
	}
	// A second daemon start reads the persisted one instead of minting.
	if again := meshNodeNameFor(""); again != first {
		t.Fatalf("name churned across restarts: %q → %q", first, again)
	}
	// And it really is on disk, not just memoised in this process.
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), first) {
		t.Fatalf("name not persisted; config.json = %s", raw)
	}
}

// An explicit --name still wins and is NOT persisted over the minted one: the
// operator said what to call it, every time.
func TestMeshNodeNameExplicitWins(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(`{"mesh_node_name":"eq-deadbeef"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CALABI_CONFIG", p)
	if got := meshNodeNameFor("build-box"); got != "build-box" {
		t.Fatalf("explicit name = %q, want build-box", got)
	}
}
