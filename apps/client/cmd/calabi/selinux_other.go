//go:build !linux

package main

// warnIfServiceCannotExec is a Linux-only check (SELinux). Nothing to do
// elsewhere — see selinux_linux.go for what it catches and why.
func warnIfServiceCannotExec() {}
