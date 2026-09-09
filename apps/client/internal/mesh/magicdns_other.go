//go:build !linux

package mesh

// The MagicDNS OS integration (assign the resolver IP + rewrite the system
// resolver config) isn't automated off Linux yet, mirroring the deferred tun
// route config. Mesh still works; node names just don't resolve via the OS
// until Windows/macOS integration lands. Callers match on
// ErrMagicDNSUnsupported (magicdns_setup.go) to log this at the volume it
// deserves — expected, not a fault.

func setupOSResolver(string, string) (string, func(), error) {
	return "", nil, ErrMagicDNSUnsupported
}
