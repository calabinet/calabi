//go:build !windows

package main

// serviceProcessPID is Windows-only (it queries the SCM). On systemd/launchd the
// manager owns the process lifecycle and the graceful stop is reliable, so there
// is no orphan to reap — return "unknown" and the caller no-ops.
func serviceProcessPID(string) (int, bool) { return 0, false }
