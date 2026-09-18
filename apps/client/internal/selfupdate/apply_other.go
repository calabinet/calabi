//go:build !darwin && !windows && !linux

package selfupdate

import (
	"context"
	"errors"
)

// applySupported says whether this GOOS has an OS-installer path at all.
// It is what turns "cannot update here" from an error into a reported state
// (Status.Reason == ReasonUnsupportedOS) the console can explain.
const applySupported = false

// installerLogHint: no installer here, nowhere to point.
const installerLogHint = ""

// applyInstaller is unsupported here. macOS and Windows run an OS installer,
// Linux swaps its own static binary; every other GOOS (the BSDs, and anything
// cross-compiled for curiosity) has neither path, so it reports "available,
// cannot install" and a person updates it by hand. Keep the symbol defined so
// the package builds everywhere.
func applyInstaller(_ context.Context, _ string) (func() error, error) {
	return nil, errors.New("selfupdate: OS installer apply is unsupported on this platform")
}
