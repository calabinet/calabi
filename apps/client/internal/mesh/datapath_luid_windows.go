//go:build windows

package mesh

import "golang.zx2c4.com/wireguard/tun"

// tunLUID returns the wintun adapter's LUID, which the Windows link config uses to
// set the interface address + routes via winipcfg. 0 if the device isn't a wintun
// NativeTun (shouldn't happen on Windows) — configureLink then reports a clear error.
func (d *WGDatapath) tunLUID() uint64 {
	if nt, ok := d.tun.(*tun.NativeTun); ok {
		return nt.LUID()
	}
	return 0
}
