package main

import (
	"sync"
	"time"
)

// Switching the daemon between calabi.net and a self-hosted server, in place.
//
// The two daemons are different programs — the platform daemon syncs with
// bff-console, the local one supervises a tunnels.yaml — so a switch ends the one
// running and starts the other. It happens inside the process rather than by
// exiting: a Windows service whose body returns keeps the process alive with
// nothing in it, systemd waits its RestartSec before bringing a service back, and
// a daemon run in a terminal would simply be gone. Each daemon releases what it
// holds when its context ends (the :7400 listener, the lock, the mesh device),
// which the next one takes over.

var (
	restartMu     sync.Mutex
	restartWanted bool
	// restartCh wakes withSignalContext, which ends the running daemon.
	restartCh = make(chan struct{}, 1)
)

// requestDaemonRestart ends the running daemon so runDaemon starts it again,
// reading the mode afresh. after gives an HTTP handler time to finish its answer.
func requestDaemonRestart(after time.Duration) {
	restartMu.Lock()
	restartWanted = true
	restartMu.Unlock()
	time.AfterFunc(after, func() {
		select {
		case restartCh <- struct{}{}:
		default:
		}
	})
}

// takeDaemonRestart reports whether the daemon that just returned was asked to
// restart, and clears the request.
func takeDaemonRestart() bool {
	restartMu.Lock()
	defer restartMu.Unlock()
	want := restartWanted
	restartWanted = false
	if want {
		// A signal still in flight belongs to this restart, not the next daemon.
		select {
		case <-restartCh:
		default:
		}
	}
	return want
}

// argsForMode is what a daemon started in the OTHER mode gets from the command
// line it was launched with: the console address and nothing else. The two
// daemons take different flags, and one's flag is the other's parse error.
// What the platform daemon's flags set (region, routes, exit device) is kept in
// the credentials file and read back from there.
func argsForMode(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		for _, name := range []string{"status-addr"} {
			dd, sd := "--"+name, "-"+name
			switch {
			case a == dd || a == sd:
				if i+1 < len(args) {
					out = append(out, a, args[i+1])
					i++
				}
			case len(a) > len(dd) && a[:len(dd)+1] == dd+"=", len(a) > len(sd) && a[:len(sd)+1] == sd+"=":
				out = append(out, a)
			}
		}
	}
	return out
}
