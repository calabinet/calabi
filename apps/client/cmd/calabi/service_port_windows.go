//go:build windows

package main

import (
	"os/exec"
	"strconv"
	"strings"
)

// pidOnPort returns the PID LISTENING on the given local TCP port, by parsing
// `netstat -ano`. This is account- and config-dir-agnostic: it finds whoever
// actually owns the port (a login-spawned user daemon OR an invisible SYSTEM
// service), which a per-user pid-file/flock probe can't. Returns (0,false) if
// nothing is listening or netstat is unavailable.
//
// netstat's data columns (TCP / address / state / pid) are not localized, so
// this is safe on non-English Windows.
func pidOnPort(port int) (int, bool) {
	out, err := exec.Command("netstat", "-ano", "-p", "tcp").Output()
	if err != nil {
		return 0, false
	}
	suffix := ":" + strconv.Itoa(port)
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		// Proto LocalAddr ForeignAddr State PID
		if len(f) < 5 || f[0] != "TCP" || f[3] != "LISTENING" {
			continue
		}
		if !strings.HasSuffix(f[1], suffix) {
			continue
		}
		if pid, err := strconv.Atoi(f[len(f)-1]); err == nil && pid > 0 {
			return pid, true
		}
	}
	return 0, false
}
