//go:build !linux && !windows && !darwin

package probe

// listenerSockets has no table to read on platforms we don't recognise; Scan
// falls back to the dial probe.
func listenerSockets() ([]listener, error) { return nil, errEnumUnsupported }
