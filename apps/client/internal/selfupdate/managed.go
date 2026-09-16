package selfupdate

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// installerManaged reports whether the running binary is the copy this
// platform's update artifact knows how to replace. See installerManagedFrom.
func (u *Updater) installerManaged() bool {
	if u.Managed != nil {
		return u.Managed()
	}
	exe, err := os.Executable()
	if err != nil {
		// Cannot tell where we are running from: do not hand ourselves an
		// installer on a guess.
		return false
	}
	// A Homebrew or scoop entry point is usually a link into the real tree; the
	// rule below is about the tree.
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return installerManagedFrom(runtime.GOOS, exe, fileExists)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// installerManagedFrom is the rule, with its inputs passed in so the matrix is
// testable on any host.
//
// The manifest is keyed by PLATFORM, but what it carries for a platform is the
// artifact of one particular WAY of installing: the NSIS setup.exe on Windows,
// the.pkg on macOS, the plain tarball on Linux. Nothing used to check that the
// running binary had been installed that way. A scoop install running as a
// Windows service was handed the desktop installer — which put a whole desktop
// app on the machine, failed to register its service over scoop's, left the
// daemon at the old version, and tried again at the next restart. A Homebrew
// install on macOS was handed the.pkg the same way.
//
// An install we cannot replace correctly must SAY so (ReasonManagedElsewhere),
// not attempt it: the right updater for it is whatever put it there.
func installerManagedFrom(goos, exe string, exists func(string) bool) bool {
	switch goos {
	case "windows":
		// The desktop installer lays calabi.exe beside calabi-desktop.exe in
		// $INSTDIR. scoop, a hand-extracted zip, or a source build do not.
		return exists(siblingOf(exe, "calabi-desktop.exe"))
	case "darwin":
		// The.pkg installs exactly one daemon path, and the LaunchDaemon execs
		// exactly that path.
		return strings.EqualFold(exe, "/Library/Application Support/Calabi/bin/calabi")
	case "linux":
		// The artifact is the tarball, swapped in place — right for install.sh
		// and a hand-extracted archive. Wrong inside a tree a package manager
		// owns: replacing the file there desyncs the manager's record of it.
		for _, tree := range []string{"/Cellar/", "/nix/store/"} {
			if strings.Contains(exe, tree) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// siblingOf joins name onto exe's directory, splitting on either separator so
// a Windows path is handled correctly when the matrix runs on another host.
func siblingOf(exe, name string) string {
	i := strings.LastIndexAny(exe, `\/`)
	if i < 0 {
		return name
	}
	return exe[:i+1] + name
}
