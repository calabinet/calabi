//go:build !linux

package mesh

import "net"

// openUAPI is a no-op off Linux: the WireGuard UAPI socket (used by `wg show`)
// isn't wired on Windows/macOS yet, matching the deferred link config there. The
// device still runs; only out-of-process `wg` introspection is unavailable. A
// nil listener tells the caller to skip the accept loop.
func openUAPI(string) (net.Listener, error) { return nil, nil }
