//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// warnIfServiceCannotExec prints the SELinux warning, if any, for the binary
// this install is about to point a unit at. Gathering only — the decision is
// selinuxExecWarning, which has no build tag so it can be tested anywhere.
func warnIfServiceCannotExec() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved // the unit follows the real file; so must the label check
	}
	if w := selinuxExecWarning(exe, selinuxEnforcing(), fileSELinuxType(exe)); w != "" {
		fmt.Fprintln(os.Stderr, "\n  warning: "+w)
	}
}

// selinuxEnforcing reports whether SELinux is in enforcing mode. Absent file =
// no SELinux on this host.
func selinuxEnforcing() bool {
	mode, err := os.ReadFile("/sys/fs/selinux/enforce")
	return err == nil && strings.TrimSpace(string(mode)) == "1"
}

// fileSELinuxType is the TYPE field of the file's security context, or "" when
// there is no label to read.
func fileSELinuxType(path string) string {
	buf := make([]byte, 256)
	n, err := unix.Getxattr(path, "security.selinux", buf)
	if err != nil || n <= 0 {
		return ""
	}
	return selinuxTypeFromLabel(string(buf[:n]))
}
