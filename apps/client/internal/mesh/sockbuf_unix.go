//go:build !windows

package mesh

import (
	"net"

	"golang.org/x/sys/unix"
)

// readSocketBuffers asks the kernel what the socket's buffers actually are.
//
// There is no portable getter on net.UDPConn, and the value matters: SetReadBuffer
// reports success on Linux even when the kernel clamped the request to
// net.core.rmem_max. Note that Linux returns DOUBLE what was set (it accounts for
// bookkeeping overhead) — that is the kernel's own convention and is reported
// verbatim rather than halved, so the number here matches what `ss -m` prints.
func readSocketBuffers(c *net.UDPConn) sockBufSizes {
	raw, err := c.SyscallConn()
	if err != nil {
		return sockBufSizes{}
	}
	var got sockBufSizes
	_ = raw.Control(func(fd uintptr) {
		if n, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF); err == nil {
			got.Read = n
		}
		if n, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF); err == nil {
			got.Write = n
		}
	})
	return got
}
