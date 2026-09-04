//go:build linux

package probe

import "os"

// listenerSockets reads the kernel's TCP tables directly. /proc/net/tcp is
// always present on a real Linux box; /proc/net/tcp6 is optional (a kernel
// built without IPv6, or a namespace without it), so its absence is not an
// error — we just report what v4 has.
func listenerSockets() ([]listener, error) {
	data, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return nil, err // no v4 table at all: let Scan fall back to dialing
	}
	out, err := parseProcNetTCP(data, false)
	if err != nil {
		return nil, err
	}
	if data6, err := os.ReadFile("/proc/net/tcp6"); err == nil {
		if ls, err := parseProcNetTCP(data6, true); err == nil {
			out = append(out, ls...)
		}
	}
	return out, nil
}
