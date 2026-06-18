//go:build windows

package main

import (
	"context"
	"log/slog"
)

// SIGHUP doesn't exist on Windows. Operators reload by bouncing the
// Windows Service (`calabi daemon restart`); this no-op keeps the
// daemon boot path uniform across platforms.
func installSIGHUP(_ *slog.Logger, _ func()) context.CancelFunc {
	return func() {}
}
