//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// On Windows we need CREATE_NEW_PROCESS_GROUP so Ctrl-C in the parent
// console doesn't kill the daemon, plus DETACHED_PROCESS to release
// the daemon from the console window entirely (it owns no stdio
// because we redirected to NUL already).
const (
	detachedProcess       = 0x00000008
	createNewProcessGroup = 0x00000200
	createNoWindow        = 0x08000000
)

func applyDetachAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: detachedProcess | createNewProcessGroup | createNoWindow,
		HideWindow:    true,
	}
}
