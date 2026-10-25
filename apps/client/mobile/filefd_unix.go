//go:build !windows

package mobile

import "golang.org/x/sys/unix"

// Mark SAF pipes nonblocking before os.NewFile, allowing Go's poller to
// interrupt blocked document IO on Close. Regular files retain seek semantics.
func prepareFileFD(fd int32) error { return unix.SetNonblock(int(fd), true) }
