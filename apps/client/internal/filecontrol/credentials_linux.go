//go:build linux

package filecontrol

import (
	"net"
	"strconv"

	"golang.org/x/sys/unix"
)

func socketDirectory(uid int) string {
	if uid == 0 {
		return "/run/calabi-file-control"
	}
	return "/tmp/calabi-file-control-" + strconv.Itoa(uid)
}

func peerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var sockErr error
	err = raw.Control(func(fd uintptr) { cred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if err != nil {
		return 0, err
	}
	if sockErr != nil {
		return 0, sockErr
	}
	return cred.Uid, nil
}
