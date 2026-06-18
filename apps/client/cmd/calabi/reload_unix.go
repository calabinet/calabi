//go:build !windows

// reload_unix.go — SIGHUP handler for the daemon.
//
// What "reload" means here:
//
//   - Re-read creds (the saved login / API key may have changed since
//     the daemon started).
//   - Mint a fresh local-token so the SPA's old token can't replay
//     against the next session.
//   - Drop the control stream and reconnect — picks up the new auth
//     credentials AND any address change in $CALABI_SERVER.
//
// We deliberately DON'T reload tunnel listeners: those live on the
// edge, the client just dials local upstreams when NEW_CONN arrives,
// so there's nothing local to "graceful-restart".
//
// Windows has no SIGHUP — operators bounce the Windows Service for
// the same effect. reload_windows.go provides a no-op installSIGHUP.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/calabi/calabi/apps/client/internal/creds"
)

// installSIGHUP wires a goroutine that, on SIGHUP, invokes onReload.
// Returns a cancel func the caller defers to clean up. onReload runs
// in the signal-watcher goroutine — keep it short or spawn its own
// worker if it needs to block.
func installSIGHUP(logger *slog.Logger, onReload func()) context.CancelFunc {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer signal.Stop(sig)
		for {
			select {
			case <-ctx.Done():
				return
			case <-sig:
				logger.Info("SIGHUP received — reloading")
				// Always mint a new local-token on reload so any
				// cached UI session must re-fetch via /v1/local-token.
				if _, err := creds.MintLocalToken(); err != nil {
					logger.Warn("local-token mint on reload failed", "err", err)
				}
				if onReload != nil {
					onReload()
				}
			}
		}
	}()
	return cancel
}
