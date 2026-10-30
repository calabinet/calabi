//go:build !windows && !linux

package rpc

// Resource accounting is provided on Windows and Linux for these load tests;
// zero here means unavailable, never zero resource usage.
func performanceProcessUsage() (float64, uint64) { return 0, 0 }
