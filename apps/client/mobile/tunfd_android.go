//go:build android

package mobile

import "golang.zx2c4.com/wireguard/tun"

// tunFromFD opens the descriptor VpnService.establish() returned. The platform
// has already detached it from its ParcelFileDescriptor, so the device owns it
// and closes it.
func tunFromFD(fd int) (tun.Device, error) {
	dev, _, err := tun.CreateUnmonitoredTUNFromFD(fd)
	return dev, err
}
