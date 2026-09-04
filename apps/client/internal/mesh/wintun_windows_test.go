//go:build windows

package mesh

import (
	"log/slog"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

// The flags the wintun package itself uses to load "wintun.dll": application dir
// + System32 only (see golang.zx2c4.com/wintun/dll.go). We mirror them so the test
// proves the exact bare-name load path the driver takes.
const (
	loadLibrarySearchApplicationDir = 0x00000200
	loadLibrarySearchSystem32       = 0x00000800
)

// After ensureWintun stages + pre-loads the bundled DLL, a BARE-name "wintun.dll"
// load — the call wireguard/tun makes — must resolve to the already-loaded module
// even though the DLL sits in neither the executable's directory nor System32.
// This is the whole mechanism the fix relies on; a real Wintun export confirms the
// resolved module is actually the driver, not some unrelated same-named DLL.
func TestEnsureWintun_BareNameResolvesAfterStaging(t *testing.T) {
	if len(wintunDLL) == 0 {
		t.Skip("no embedded wintun.dll for this arch")
	}

	// Sanity: the staged file lands under the user cache, NOT next to the test
	// binary or in System32 — so a successful bare load can only come from our
	// pre-load, not from a stray DLL on the search path.
	path, err := extractWintun()
	if err != nil {
		t.Fatalf("extractWintun: %v", err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Size() != int64(len(wintunDLL)) {
		t.Fatalf("staged DLL missing/wrong size at %s: %v", path, err)
	}

	if err := ensureWintun(slog.Default()); err != nil {
		t.Fatalf("ensureWintun: %v", err)
	}

	h, err := windows.LoadLibraryEx("wintun.dll", 0, loadLibrarySearchApplicationDir|loadLibrarySearchSystem32)
	if err != nil {
		t.Fatalf("bare-name wintun.dll load failed after ensureWintun (the fix's core mechanism): %v", err)
	}
	if _, err := windows.GetProcAddress(h, "WintunCreateAdapter"); err != nil {
		t.Fatalf("resolved module is not Wintun (WintunCreateAdapter missing): %v", err)
	}
}
