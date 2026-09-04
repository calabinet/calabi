package mesh

import "log/slog"

// Datapath is the WireGuard tun data plane the Controller drives. The REAL
// implementation (wireguard-go + a tun device) is a real-machine slice: it needs
// a tun device and elevated privileges (wintun.dll on Windows), so it can't run
// in CI. Until then LoggingDatapath is the safe default / dry run, and tests use
// a recording fake. (MESH.2).
type Datapath interface {
	// SetConfig applies the desired WG peer set. Called on every netmap update
	// with the FULL config; implementations diff against current state and are
	// expected to be idempotent.
	SetConfig(cfg WGConfig) error
	Close() error
}

// LoggingDatapath is a no-op Datapath that logs the intended config. It lets the
// control-plane loop (enroll + netmap + config derivation) run end to end for a
// dry run before the real tun datapath exists.
type LoggingDatapath struct{ Logger *slog.Logger }

// SetConfig logs a one-line summary of the desired state.
func (d LoggingDatapath) SetConfig(cfg WGConfig) error {
	d.Logger.Info("mesh datapath (dry-run) SetConfig",
		"overlay", cfg.OverlayAddr, "peers", len(cfg.Peers))
	return nil
}

// Close is a no-op.
func (LoggingDatapath) Close() error { return nil }
