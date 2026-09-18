//go:build !android

package mobile

import (
	"errors"

	"golang.zx2c4.com/wireguard/tun"
)

// tunFromFD has no implementation here yet: iOS's utun descriptor lands with
// , and a desktop never builds this
// package except to test it.
func tunFromFD(int) (tun.Device, error) {
	return nil, errors.New("mobile: opening a tun descriptor is not implemented on this platform")
}
