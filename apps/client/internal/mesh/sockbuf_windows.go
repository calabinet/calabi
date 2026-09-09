package mesh

import (
	"net"

	"golang.org/x/sys/windows"
)

// readSocketBuffers asks Winsock what the socket's buffers actually are. Same
// reason as the unix build: SetReadBuffer's success says nothing about the size
// the stack settled on.
func readSocketBuffers(c *net.UDPConn) sockBufSizes {
	raw, err := c.SyscallConn()
	if err != nil {
		return sockBufSizes{}
	}
	var got sockBufSizes
	_ = raw.Control(func(fd uintptr) {
		h := windows.Handle(fd)
		if n, err := windows.GetsockoptInt(h, windows.SOL_SOCKET, windows.SO_RCVBUF); err == nil {
			got.Read = n
		}
		if n, err := windows.GetsockoptInt(h, windows.SOL_SOCKET, windows.SO_SNDBUF); err == nil {
			got.Write = n
		}
	})
	return got
}
