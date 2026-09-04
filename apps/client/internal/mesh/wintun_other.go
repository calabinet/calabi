//go:build !windows

package mesh

import "log/slog"

// ensureWintun is a no-op off Windows: tun creation there uses the OS-native
// driver (Linux /dev/net/tun, etc.), not wintun.dll.
func ensureWintun(*slog.Logger) error { return nil }
