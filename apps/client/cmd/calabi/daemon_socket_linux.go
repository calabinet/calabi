//go:build linux

package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

func listenDaemonSocket(path string) (*net.UnixListener, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("management socket requires a clean absolute path")
	}
	uid := uint32(os.Geteuid())
	var st unix.Stat_t
	if err := unix.Lstat(filepath.Dir(path), &st); err != nil {
		return nil, err
	}
	if st.Uid != uid || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0777 != 0700 {
		return nil, errors.New("management socket directory must be owned by the daemon and have mode 0700")
	}
	switch err := unix.Lstat(path, &st); {
	case err == nil:
		if st.Uid != uid || st.Mode&unix.S_IFMT != unix.S_IFSOCK {
			return nil, errors.New("management socket path is not an owned socket")
		}
		conn, err := net.DialTimeout("unix", path, 250*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil, errors.New("management socket is already active")
		}
		if !errors.Is(err, unix.ECONNREFUSED) {
			return nil, err
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	case !errors.Is(err, os.ErrNotExist):
		return nil, err
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}
