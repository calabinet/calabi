//go:build darwin

package probe

import (
	"context"
	"os/exec"
	"time"
)

// listenerSockets shells out to netstat on macOS. There is no stable public API
// for the socket table (the private libproc route needs cgo and still can't
// other users' sockets without root), and netstat -an is unprivileged, present
// on every macOS, and prints the bind address we need. The 2s cap keeps a wedged
// netstat from hanging the diagnostics page — Scan then falls back to dialing.
func listenerSockets() ([]listener, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "netstat", "-an", "-p", "tcp").Output()
	if err != nil {
		return nil, err
	}
	return parseNetstat(out)
}
