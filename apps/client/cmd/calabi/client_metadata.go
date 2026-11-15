package main

import "github.com/calabinet/calabi/apps/client/internal/platform/clientreg"

func init() {
	// This existing build stamp is also used by the desktop update channel.
	clientreg.DesktopVersion = desktopProductVersion
}
