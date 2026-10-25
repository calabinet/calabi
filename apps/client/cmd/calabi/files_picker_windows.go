//go:build windows

package main

import (
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

// Windows common dialogs run solely in the ordinary user agent. Neither the
// webview nor the machine service can supply an arbitrary path to open/save.
type openFileName struct {
	size             uint32
	owner            windows.Handle
	instance         windows.Handle
	filter           *uint16
	customFilter     *uint16
	maxCustomFilter  uint32
	filterIndex      uint32
	file             *uint16
	maxFile          uint32
	fileTitle        *uint16
	maxFileTitle     uint32
	initialDir       *uint16
	title            *uint16
	flags            uint32
	fileOffset       uint16
	fileExtension    uint16
	defaultExtension *uint16
	customData       uintptr
	hook             uintptr
	templateName     *uint16
	reserved         unsafe.Pointer
	reserved2        uint32
	flagsEx          uint32
}

var fileDialogs = windows.NewLazySystemDLL("comdlg32.dll")

func transferDialog(save bool, name string, owner uint64) ([]string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := windows.CoInitializeEx(0, 2); err != nil && !errors.Is(err, syscall.Errno(1)) {
		return nil, err
	}
	defer windows.CoUninitialize()
	buffer := make([]uint16, 64<<10)
	if name != "" {
		s, err := windows.UTF16FromString(name)
		if err != nil {
			return nil, err
		}
		copy(buffer, s)
	}
	filter := []uint16{'A', 'l', 'l', ' ', 'f', 'i', 'l', 'e', 's', 0, '*', '.', '*', 0, 0}
	ofn := openFileName{file: &buffer[0], maxFile: uint32(len(buffer)), filter: &filter[0], filterIndex: 1, flags: 0x00080000 | 0x00000008 | 0x00001000 | 0x02000000}
	ofn.size = uint32(unsafe.Sizeof(ofn))
	ofn.owner = windows.Handle(owner)
	proc := fileDialogs.NewProc("GetOpenFileNameW")
	if save {
		ofn.flags |= 0x00000002
		proc = fileDialogs.NewProc("GetSaveFileNameW")
	} else {
		ofn.flags |= 0x00000200 | 0x00000800
	}
	ok, _, _ := proc.Call(uintptr(unsafe.Pointer(&ofn)))
	runtime.KeepAlive(buffer)
	runtime.KeepAlive(filter)
	if ok == 0 {
		code, _, _ := fileDialogs.NewProc("CommDlgExtendedError").Call()
		if code != 0 {
			return nil, fmt.Errorf("file dialog failed (%x)", code)
		}
		return nil, nil
	}
	var parts []string
	for start := 0; start < len(buffer) && buffer[start] != 0; {
		end := start
		for end < len(buffer) && buffer[end] != 0 {
			end++
		}
		if end == len(buffer) {
			return nil, errors.New("invalid file dialog result")
		}
		parts = append(parts, windows.UTF16ToString(buffer[start:end]))
		start = end + 1
	}
	if len(parts) > 1 {
		dir := parts[0]
		out := make([]string, 0, len(parts)-1)
		for _, name := range parts[1:] {
			out = append(out, filepath.Join(dir, name))
		}
		parts = out
	}
	if len(parts) > 32 {
		return nil, errors.New("choose at most 32 files")
	}
	return parts, nil
}
func pickTransferFiles(owner uint64) ([]string, error) { return transferDialog(false, "", owner) }
func pickTransferDestination(name string, owner uint64) (string, error) {
	paths, err := transferDialog(true, name, owner)
	if err != nil || len(paths) == 0 {
		return "", err
	}
	return paths[0], nil
}
