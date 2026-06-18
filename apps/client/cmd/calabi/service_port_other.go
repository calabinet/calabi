//go:build !windows

package main

// pidOnPort is implemented via netstat on Windows, where the account/config-dir
// split between a user daemon and a SYSTEM service makes the per-user pid file
// unreliable. On systemd/launchd the same-account pid file works, so callers
// fall back to that — return "unknown" here.
func pidOnPort(int) (int, bool) { return 0, false }
