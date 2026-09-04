//go:build !windows

package mesh

// tunLUID is Windows-only (a wintun concept); elsewhere link config keys off the
// interface name instead, so this is always 0.
func (d *WGDatapath) tunLUID() uint64 { return 0 }
