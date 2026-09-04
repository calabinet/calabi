//go:build !darwin && !windows

package selfupdate

import (
	"context"
	"errors"
)

// applyInstaller is unsupported off macOS/Windows — the installer-driven
// self-update model (Option A) is those two platforms only; Linux is served by
// its distro package manager. CheckAndApply normally never reaches here because
// a mac/win manifest has no artifact for a Linux platform key, but keep the
// symbol defined so the package builds everywhere.
func applyInstaller(_ context.Context, _ string) error {
	return errors.New("selfupdate: OS installer apply is unsupported on this platform")
}
