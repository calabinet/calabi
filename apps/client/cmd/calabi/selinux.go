package main

import (
	"fmt"
	"path"
)

// The SELinux exec-label check for `daemon install`, minus the two things that
// only exist on Linux (reading /sys/fs/selinux/enforce and the file's xattr).
//
// The decision lives here, with no build tag, so it can be tested on any
// machine. The Linux file gathers the inputs; this decides. A check whose logic
// only compiles on the OS none of us develops on is a check nobody exercises.
//
// What it catches: `daemon install` writes the RUNNING executable's path into
// the unit's ExecStart, wherever that happens to be. On an SELinux-enforcing
// host that is not enough — a file keeps the label of the directory it was
// created in, and a systemd service may not execute one labelled admin_home_t
// (anything under /root) or user_home_t (under /home). The install reports
// success, the service fails with status=203/EXEC, and because the process never
// starts there is not one line of the daemon's own log to explain it. Running
// the same binary by hand works, since an interactive shell is unconfined —
// which is what makes it easy to misread.

// execTypesServicesMayRun are the labels a systemd service can execute out of
// the box. bin_t is what /usr/bin, /usr/local/bin and /usr/sbin give a file that
// lands there.
var execTypesServicesMayRun = map[string]bool{"bin_t": true, "sbin_t": true}

// selinuxExecWarning returns what to tell the operator, or "" when there is
// nothing to say.
//
// enforcing=false covers both "no SELinux" and permissive; permissive logs the
// denial but still executes, so it is not worth a warning. An empty label means
// we could not read one — also nothing to say, rather than a guess.
//
// A WARNING, never a refusal: a site with its own policy module may well have
// granted this, and a label alone cannot show that.
func selinuxExecWarning(exePath string, enforcing bool, label string) string {
	if !enforcing || label == "" || execTypesServicesMayRun[label] {
		return ""
	}
	return fmt.Sprintf(`SELinux is enforcing and %s is labelled %s.
  A systemd service may not execute that label, so the unit is likely to fail
  with "status=203/EXEC" and produce NO log of its own (the process never runs;
  the reason is only in: journalctl -u <service> and ausearch -m avc -ts recent).
  Running the binary by hand still works, which makes this easy to misread.

%s
  If your own policy module already allows this label, ignore the above.`,
		exePath, label, selinuxRemedy(exePath))
}

// binDirs are the directories whose policy gives a file bin_t — where a service
// may execute from.
var binDirs = map[string]bool{
	"/usr/bin": true, "/usr/sbin": true, "/bin": true, "/sbin": true,
	"/usr/local/bin": true, "/usr/local/sbin": true,
}

// selinuxRemedy is the fix to print, which depends on WHERE the file already is.
//
// A file in /usr/local/bin that is still labelled admin_home_t got there with
// `mv`, which preserves the label (only `cp` and a fresh write take the target
// directory's). Telling that operator to move it produces
// `mv /usr/local/bin/calabi /usr/local/bin/calabi` — advice that is both absurd
// and useless, since relabelling is the whole of what is needed. Observed
// 2026-09-06, printed at a person who had just followed our own instructions.
func selinuxRemedy(exePath string) string {
	if binDirs[path.Dir(exePath)] {
		return "  It is already somewhere services may run from — it just kept the label of\n" +
			"  wherever it was copied from (`mv` preserves it; only `cp` relabels). Relabel it:\n" +
			"      sudo restorecon -v " + exePath + "\n" +
			"      sudo systemctl restart <service>"
	}
	return "  Put it somewhere services may run from, then re-install:\n" +
		"      sudo mv " + exePath + " /usr/local/bin/calabi\n" +
		"      sudo chown root:root /usr/local/bin/calabi\n" +
		"      sudo restorecon -v /usr/local/bin/calabi"
}

// selinuxTypeFromLabel pulls the TYPE out of a "user:role:type:level" context —
// the third field. Returns "" for anything that isn't one, including the empty
// string and the NUL-padded forms an xattr read can hand back.
func selinuxTypeFromLabel(raw string) string {
	// Trim trailing NULs: the xattr value is NUL-terminated on most filesystems.
	for len(raw) > 0 && raw[len(raw)-1] == 0 {
		raw = raw[:len(raw)-1]
	}
	fields := splitN(raw, ':', 4)
	if len(fields) < 3 || fields[2] == "" {
		return ""
	}
	return fields[2]
}

// splitN is strings.SplitN without the import, kept local so this file stays
// dependency-free and obviously pure.
func splitN(s string, sep byte, n int) []string {
	var out []string
	start := 0
	for i := 0; i < len(s) && len(out) < n-1; i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}
