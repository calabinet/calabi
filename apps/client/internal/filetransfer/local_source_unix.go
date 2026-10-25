//go:build unix

package filetransfer

import (
	"fmt"
	"os"
	"syscall"
)

// Avoid blocking on a FIFO substituted for a previously selected regular file.
// O_NONBLOCK has no effect on regular-file reads; Stat rejects special files.
func openLocalSource(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

func localFileIdentity(_ *os.File, info os.FileInfo) (string, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errLocalSource
	}
	return fmt.Sprintf("%x/%x", st.Dev, st.Ino), nil
}
