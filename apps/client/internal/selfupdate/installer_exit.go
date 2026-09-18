package selfupdate

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
)

// installerExited is what it means when a launched installer's process ends
// and this daemon is still here to see it: the update did not take, whatever
// the exit code. Every installer stops this service BEFORE it swaps anything in
// (the NSIS PREINSTALL hook, the pkg postinstall), so a daemon that outlives
// its installer is still the old version.
//
// Without this the agent latched "updating" at launch and nothing ever cleared
// it. The first macOS self-update failed writing the app bundle, exited, and
// the console spun until someone restarted the service by hand (2026-09-16).
func installerExited(err error) error {
	if err == nil {
		return errors.New("selfupdate: the installer exited without restarting this service; the update did not take" + installerLogHint)
	}
	return fmt.Errorf("selfupdate: the installer failed (%w)%s", err, installerLogHint)
}

// maxLastLine caps what one line of installer output may add to an error the
// console renders.
const maxLastLine = 300

// lastLine returns the last non-empty line of a small log file, trimmed and
// capped, or "" when there is none to read.
func lastLine(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	b = bytes.TrimSpace(b)
	if i := bytes.LastIndexByte(b, '\n'); i >= 0 {
		b = b[i+1:]
	}
	line := strings.TrimSpace(string(b))
	if r := []rune(line); len(r) > maxLastLine {
		line = string(r[:maxLastLine]) + "…"
	}
	return line
}
