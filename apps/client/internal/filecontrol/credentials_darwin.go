//go:build darwin

package filecontrol

import (
	"net"
	"strconv"

	"golang.org/x/sys/unix"
)

func socketDirectory(uid int) string {
	if uid == 0 {
		return "/var/run/calabi-file-control"
	}
	return "/tmp/calabi-file-control-" + strconv.Itoa(uid)
}

// LOCAL_PEERCRED is supplied by the kernel on both ends of a Unix stream.
// Neither the request body nor the socket file's owner authenticates a caller.
func peerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Xucred
	var sockErr error
	err = raw.Control(func(fd uintptr) { cred, sockErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED) })
	if err != nil {
		return 0, err
	}
	if sockErr != nil {
		return 0, sockErr
	}
	return cred.Uid, nil
}
