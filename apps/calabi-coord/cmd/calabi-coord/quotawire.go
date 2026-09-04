package main

import (
	"log/slog"
	"strconv"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
)

// staticNodeQuota builds the node cap from CALABI_COORD_NODE_QUOTA:
// a positive integer caps every meshnet at that many nodes; unset / 0 / negative
// means unlimited. It's the self-hosted + dev cap, and the platform
// build's fallback when quota-svc isn't wired (see wire_platform.go). The
// multi-tenant per-plan cap is the quota-svc-backed NodeQuota.
func staticNodeQuota(logger *slog.Logger) core.NodeQuota {
	raw := env("NODE_QUOTA")
	if raw == "" {
		return core.UnlimitedNodeQuota{}
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		if err != nil {
			logger.Warn("CALABI_COORD_NODE_QUOTA not an integer; treating as unlimited", "value", raw)
		}
		return core.UnlimitedNodeQuota{}
	}
	logger.Info("mesh node quota (static, per meshnet)", "limit", n)
	return core.StaticNodeQuota{Limit: n}
}
