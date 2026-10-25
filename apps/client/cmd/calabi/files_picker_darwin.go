//go:build darwin

package main

import (
	"bytes"
	"errors"
	"os/exec"
	"strings"
)

// The system chooser is invoked in the ordinary user's agent, never by the
// root daemon. Script source is constant; display names are separate arguments.
func pickTransferFiles(uint64) ([]string, error) {
	script := `try
set selectedFiles to choose file with prompt "Select files to send with Calabi" with multiple selections allowed
if (count selectedFiles) > 32 then error "Select at most 32 files"
set resultPaths to ""
repeat with selectedFile in selectedFiles
set selectedPath to POSIX path of selectedFile
if selectedPath contains (ASCII character 31) then error "Unsupported control character in path"
set resultPaths to resultPaths & selectedPath & (ASCII character 31)
end repeat
return resultPaths
on error number -128
return ""
end try`
	body, err := exec.Command("/usr/bin/osascript", "-e", script).Output()
	if err != nil {
		return nil, errors.New("file selection cancelled or unavailable")
	}
	body = bytes.TrimSuffix(body, []byte("\n"))
	if len(body) == 0 {
		return nil, nil
	}
	if len(body) > 128<<10 || body[len(body)-1] != 31 {
		return nil, errors.New("invalid system file selection")
	}
	paths := strings.Split(string(body[:len(body)-1]), "\x1f")
	if len(paths) > 32 {
		return nil, errors.New("select at most 32 files")
	}
	return paths, nil
}

func pickTransferDestination(name string, _ uint64) (string, error) {
	script := `on run argv
try
set destination to choose file name with prompt "Save verified Calabi file" default name (item 1 of argv)
return POSIX path of destination
on error number -128
return ""
end try
end run`
	body, err := exec.Command("/usr/bin/osascript", "-e", script, "--", name).Output()
	if err != nil {
		return "", errors.New("file saving cancelled or unavailable")
	}
	path := strings.TrimSuffix(string(body), "\n")
	if len(path) > 4096 || strings.ContainsRune(path, 0) {
		return "", errors.New("invalid system save destination")
	}
	return path, nil
}
