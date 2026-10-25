//go:build windows

package filetransfer

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
)

func openLocalSource(path string) (*os.File, error) { return os.Open(path) }

func localFileIdentity(f *os.File, _ os.FileInfo) (string, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x/%x/%x", info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow), nil
}
