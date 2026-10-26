//go:build !linux

package main

import (
	"fmt"
	"os"
)

func runFileService([]string) int {
	fmt.Fprintln(os.Stderr, "file service management requires systemd Linux")
	return 1
}
func installCompanionFiles([]string) error   { return nil }
func uninstallCompanionFiles([]string) error { return nil }
