//go:build windows

package mesh

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// ensureWintun makes the bundled Wintun driver available before the tun is
// created. wireguard/tun loads "wintun.dll" via LoadLibraryEx, searching ONLY the
// executable's directory and System32 — never PATH or the working directory. So
// rather than make users drop the DLL into one of those, we embed the arch-matched
// DLL (see wintun_embed_windows_*.go), extract it to a per-user cache path NAMED
// wintun.dll, and pre-load it by full path. Windows then reuses that already-loaded
// module (matched by base name "wintun.dll") when the wintun package loads it later,
// regardless of the restricted search dirs.
//
// Best-effort: on any failure we log and return nil so CreateTUN still falls back
// to a system-installed wintun.dll (e.g. one placed in System32 by hand or by an
// installer). The loaded handle is deliberately never freed — it must stay resident
// through tun creation and the device's lifetime.
func ensureWintun(logger *slog.Logger) error {
	if len(wintunDLL) == 0 {
		return nil // no embedded DLL for this arch — rely on a system-installed one
	}
	path, err := extractWintun()
	if err != nil {
		warnWintun(logger, "could not stage bundled wintun.dll; relying on a system-installed one", "err", err)
		return nil
	}
	if _, err := windows.LoadLibraryEx(path, 0, windows.LOAD_WITH_ALTERED_SEARCH_PATH); err != nil {
		warnWintun(logger, "pre-loading bundled wintun.dll failed; relying on a system-installed one", "path", path, "err", err)
		return nil
	}
	if logger != nil {
		logger.Debug("mesh: bundled wintun.dll pre-loaded", "path", path)
	}
	return nil
}

func warnWintun(logger *slog.Logger, msg string, args ...any) {
	if logger != nil {
		logger.Warn("mesh: "+msg, args...)
	}
}

// extractWintun writes the embedded DLL to <cache>/calabi/wintun/<sha8>/wintun.dll
// (idempotent — skipped when already present at the right size) and returns its
// path. The content hash in the directory keeps versions from colliding; the file
// itself stays named wintun.dll so Windows' already-loaded-module match works.
func extractWintun() (string, error) {
	sum := sha256.Sum256(wintunDLL)
	tag := hex.EncodeToString(sum[:])[:16]
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		base = os.TempDir()
	}
	dir := filepath.Join(base, "calabi", "wintun", tag)
	path := filepath.Join(dir, "wintun.dll")
	if fi, err := os.Stat(path); err == nil && fi.Size() == int64(len(wintunDLL)) {
		return path, nil // already staged
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	// Atomic write (temp in the same dir + rename) so a concurrent daemon never
	// observes a half-written DLL.
	tmp, err := os.CreateTemp(dir, "wintun-*.tmp")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(wintunDLL); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return "", err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		// A racing process may have created it first — accept a good file.
		if fi, statErr := os.Stat(path); statErr == nil && fi.Size() == int64(len(wintunDLL)) {
			return path, nil
		}
		return "", err
	}
	return path, nil
}
