//go:build !windows

package relay

// Resource accounting is provided by the Windows runner for these load tests;
// zero here means unavailable, never zero resource usage.
func performanceProcessUsage() (float64, uint64) { return 0, 0 }
