package mesh

import (
	"log/slog"
	"net"
)

// Socket buffer sizing for the direct-path UDP socket.
//
// wireguard-go is a USERSPACE datapath: every packet the kernel receives waits
// in the socket's receive buffer until a Go goroutine is scheduled and reads it.
// Whatever does not fit is dropped by the kernel, before any of our code runs —
// silently, and invisibly to the inner TCP, which sees only a hole.
//
// The default is far too small for a fast path. macOS ships
// net.inet.udp.recvspace at a few tens of KB, which at 1280-byte packets is a
// few dozen packets: one burst from a peer on a 50 Mbit uplink overruns it
// during a single scheduler quantum. Both Tailscale and wireguard-go's own
// StdNetBind raise this deliberately; this bind (meshBind) opens its own socket
// and never did.
//
// The ladder exists because the platforms disagree about what "too big" means.
// Linux CLAMPS to net.core.rmem_max and reports success; the BSDs (macOS
// included) REFUSE with ENOBUFS above kern.ipc.maxsockbuf and leave the previous
// value in place. A single large SetReadBuffer would therefore silently do
// nothing on exactly the platform that needs it most, so we walk down until one
// sticks — and then read back what we actually got, because a success on Linux
// still means "you got rmem_max, not what you asked for".
var sockBufLadder = []int{7 << 20, 4 << 20, 2 << 20, 1 << 20, 512 << 10, 256 << 10}

// sockBufSizes is what a socket ended up with, in bytes. Zero means the platform
// would not tell us (getsockopt failed); it does NOT mean the buffer is zero.
type sockBufSizes struct {
	Read  int
	Write int
}

// tuneSocketBuffers raises the socket's send and receive buffers as far as the
// platform allows, and reports what they actually are afterwards.
//
// Failures are not fatal: a small buffer costs throughput under load, which is
// strictly better than refusing to bring the mesh up. But the result IS
// reported, because "we asked for 7 MiB and the OS gave us 200 KiB" is the
// difference between a datapath that keeps up and one that does not, and
// nothing else in the system would ever show it.
func tuneSocketBuffers(c *net.UDPConn, logger *slog.Logger) sockBufSizes {
	applyLadder(c.SetReadBuffer)
	applyLadder(c.SetWriteBuffer)
	got := readSocketBuffers(c)
	if logger != nil {
		logger.Debug("mesh: direct-path socket buffers",
			"rx_bytes", got.Read, "tx_bytes", got.Write, "wanted_bytes", sockBufLadder[0])
	}
	return got
}

// applyLadder calls set with successively smaller sizes until one is accepted,
// and returns the size that stuck (0 if none was).
//
// Split out from tuneSocketBuffers because this is the part with a decision in
// it, and the decision is untestable through a real socket: whether a given size
// is accepted depends entirely on the host's sysctls, so a test driving a real
// socket would be asserting something about the machine it runs on rather than
// about this code.
func applyLadder(set func(int) error) int {
	for _, n := range sockBufLadder {
		if err := set(n); err == nil {
			return n
		}
	}
	return 0
}
