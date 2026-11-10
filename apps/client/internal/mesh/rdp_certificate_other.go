//go:build !windows

package mesh

import (
	"context"
	"log/slog"
)

func startRDPCertificateReporter(context.Context, *CoordClient, *slog.Logger) {}
