package main

import (
	"strings"
	"testing"
)

// The case this exists for is the one that looks fine: install succeeds, the
// binary runs by hand, and the service dies with 203 and no log.
func TestSELinuxExecWarning(t *testing.T) {
	cases := []struct {
		name      string
		enforcing bool
		label     string
		warn      bool
	}{
		{"a binary under /root", true, "admin_home_t", true},
		{"a binary under /home", true, "user_home_t", true},
		{"a binary under /opt", true, "usr_t", true},
		{"unpacked into /tmp", true, "tmp_t", true},

		{"already in /usr/local/bin", true, "bin_t", false},
		{"an sbin binary", true, "sbin_t", false},

		// Permissive logs the denial but still executes, so warning would be
		// noise on a machine where nothing is actually broken.
		{"permissive", false, "admin_home_t", false},
		{"no selinux at all", false, "", false},
		// No label to read is not a guess we should make either way.
		{"unlabelled but enforcing", true, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := selinuxExecWarning("/root/calabi-pro/calabi", c.enforcing, c.label)
			if (got != "") != c.warn {
				t.Fatalf("warn=%v, want %v (got %q)", got != "", c.warn, got)
			}
			if !c.warn {
				return
			}
			// The warning has to carry the three things that make it actionable:
			// which file, what is wrong, and the symptom the operator will
			// otherwise be staring at with no explanation.
			for _, want := range []string{"/root/calabi-pro/calabi", c.label, "203/EXEC", "/usr/local/bin/calabi"} {
				if !strings.Contains(got, want) {
					t.Errorf("warning does not mention %q:\n%s", want, got)
				}
			}
		})
	}
}

func TestSELinuxTypeFromLabel(t *testing.T) {
	cases := map[string]string{
		"unconfined_u:object_r:admin_home_t:s0":    "admin_home_t",
		"system_u:object_r:bin_t:s0":               "bin_t",
		"unconfined_u:object_r:user_home_t:s0\x00": "user_home_t", // xattrs come back NUL-terminated
		"system_u:object_r:bin_t:s0:c0.c1023":      "bin_t",       // MLS range, still field 3
		"":                                         "",
		"garbage":                                  "",
		"only:two":                                 "",
		"a:b::s0":                                  "", // empty type is no answer
	}
	for in, want := range cases {
		if got := selinuxTypeFromLabel(in); got != want {
			t.Errorf("selinuxTypeFromLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

// The remedy depends on WHERE the file already is. A binary in /usr/local/bin
// that still carries admin_home_t got there with `mv`, which preserves the
// label; only `cp` and a fresh write take the target directory's. Telling that
// operator to move it printed `mv /usr/local/bin/calabi /usr/local/bin/calabi` —
// absurd, and useless, since relabelling is the whole of what is needed.
// Observed 2026-09-06 at someone who had just followed our own instructions.
func TestSELinuxRemedyDependsOnWhereTheFileIs(t *testing.T) {
	t.Run("already in a bin dir: relabel, do not move", func(t *testing.T) {
		got := selinuxRemedy("/usr/local/bin/calabi")
		if strings.Contains(got, "mv ") {
			t.Errorf("advises a move for a file already in place:\n%s", got)
		}
		if !strings.Contains(got, "restorecon -v /usr/local/bin/calabi") {
			t.Errorf("does not advise relabelling:\n%s", got)
		}
	})
	t.Run("outside a bin dir: move then relabel", func(t *testing.T) {
		got := selinuxRemedy("/root/calabi-pro/calabi")
		if !strings.Contains(got, "mv /root/calabi-pro/calabi /usr/local/bin/calabi") {
			t.Errorf("does not advise the move:\n%s", got)
		}
		if !strings.Contains(got, "restorecon") {
			t.Errorf("does not advise relabelling after the move:\n%s", got)
		}
	})
	// Never, under any path, tell someone to move a file onto itself.
	for _, p := range []string{"/usr/bin/calabi", "/usr/local/bin/calabi", "/sbin/calabi", "/usr/local/sbin/calabi"} {
		if strings.Contains(selinuxRemedy(p), "mv "+p+" "+p) {
			t.Errorf("%s: advises moving the file onto itself", p)
		}
	}
}
