package mesh

import (
	"errors"
	"log/slog"

	"github.com/calabi/calabi/apps/client/internal/mesh/magicdns"
)

// ErrMagicDNSUnsupported means the OS integration (assign the resolver IP +
// rewrite the system resolver config) isn't wired on this platform — today,
// anything but Linux. Mesh itself is unaffected; only OS-level name resolution
// is missing.
//
// It is declared here rather than in the !linux shim so callers can tell this
// apart from a genuine failure on EVERY platform: "not implemented here" and
// "it broke" deserve different volumes in the log, and a caller that cannot
// distinguish them ends up warning about the expected case on every start.
var ErrMagicDNSUnsupported = errors.New("mesh: MagicDNS OS integration not supported on this platform")

const (
	// magicDNSIP is where the resolver listens (Tailscale-style; kept off the tun
	// so queries to it stay local). magicDNSSuffix is the search domain, so both
	// "<node>" and "<node>.mesh" resolve.
	magicDNSIP     = "100.100.100.100"
	magicDNSSuffix = "mesh"
)

// StartMagicDNS brings up the MagicDNS resolver and points the OS at it. Feed the
// returned DNSSink each netmap's records (via Controller.DNS). Returns an error
// when OS integration isn't available (e.g. off Linux) — mesh still works, only
// name resolution is unavailable — so callers should degrade to a warning, not
// fail. cleanup stops the server and restores the system resolver config.
func StartMagicDNS(logger *slog.Logger) (DNSSink, func(), error) {
	upstream, osCleanup, err := setupOSResolver(magicDNSIP, magicDNSSuffix)
	if err != nil {
		return nil, nil, err
	}
	r := magicdns.New(magicDNSSuffix, upstream, logger)
	if err := r.Serve(magicDNSIP + ":53"); err != nil {
		osCleanup()
		return nil, nil, err
	}
	cleanup := func() {
		_ = r.Close()
		osCleanup()
	}
	return r, cleanup, nil
}
