package mesh

import (
	"log/slog"

	"github.com/calabi/calabi/apps/client/internal/mesh/magicdns"
)

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
