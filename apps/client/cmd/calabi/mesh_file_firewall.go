package main

import (
	"context"
	"fmt"
	"os"

	"github.com/calabinet/calabi/apps/client/internal/filecontrol"
)

// Used by the elevated Windows installer/uninstaller, without starting a file
// agent or reading an account configuration. No program-path override exists.
func runMeshFileFirewall(args []string) int {
	if len(args) != 1 || (args[0] != "install" && args[0] != "remove") {
		fmt.Fprintln(os.Stderr, "usage: calabi mesh files firewall install|remove (Windows administrator only)")
		return 2
	}
	if err := filecontrol.InstallationFirewall(context.Background(), args[0] == "install"); err != nil {
		fmt.Fprintln(os.Stderr, "calabi file firewall:", err)
		return 1
	}
	return 0
}
