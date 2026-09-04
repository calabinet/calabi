//go:build !linux

package mesh

import "errors"

// errMagicDNSUnsupported: the MagicDNS OS integration (assign the resolver IP +
// rewrite the system resolver config) isn't automated off Linux yet, mirroring
// the deferred tun route config. Mesh still works; node names just don't resolve
// via the OS until Windows/macOS integration lands.
var errMagicDNSUnsupported = errors.New("mesh: MagicDNS OS integration not supported on this platform")

func setupOSResolver(string, string) (string, func(), error) {
	return "", nil, errMagicDNSUnsupported
}
