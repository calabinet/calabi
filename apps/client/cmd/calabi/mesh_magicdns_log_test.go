package main

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"testing"

	"github.com/calabinet/calabi/apps/client/internal/mesh"
)

// The level this picks is the whole point of the function, and it is exactly
// the kind of thing that regresses silently: someone adds an error path, routes
// it through here, and either a real failure goes quiet or Windows starts
// warning on every start again about a feature we no longer offer.
//
// Both branches run on every OS: mesh.ErrMagicDNSUnsupported is declared
// without a build tag precisely so this test does not depend on GOOS. A test
// whose verdict is decided by the machine it runs on is not a test.
func TestMagicDNSUnavailableLogLevel(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want slog.Level
	}{
		{"unsupported platform is expected, not a fault", mesh.ErrMagicDNSUnsupported, slog.LevelDebug},
		{"wrapped sentinel still counts", fmt.Errorf("start: %w", mesh.ErrMagicDNSUnsupported), slog.LevelDebug},
		{"a real failure is still a warning", errors.New("listen 100.100.100.100:53: permission denied"), slog.LevelWarn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			// LevelDebug so BOTH records reach the buffer — a handler that
			// filtered debug out would make the first two cases pass by
			// printing nothing, which is not what is being asserted.
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			logMagicDNSUnavailable(logger, tc.err)

			out := buf.String()
			if want := "level=" + tc.want.String(); !bytes.Contains(buf.Bytes(), []byte(want)) {
				t.Errorf("logged %q, want %s", out, want)
			}
			if !bytes.Contains(buf.Bytes(), []byte("MagicDNS")) {
				t.Errorf("logged %q, want it to name MagicDNS", out)
			}
		})
	}
}
