//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

// applyDetachAttr puts the child into its own process group so a
// Ctrl-C in the parent terminal doesn't propagate. Setsid also
// disowns the controlling terminal entirely, which is what we want
// for a long-running daemon.
func applyDetachAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
}
