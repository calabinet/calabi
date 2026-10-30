//go:build linux

package rpc

import "syscall"

func performanceProcessUsage() (float64, uint64) {
	var r syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &r); err != nil {
		return 0, 0
	}
	seconds := float64(r.Utime.Sec+r.Stime.Sec) + float64(r.Utime.Usec+r.Stime.Usec)/1e6
	return seconds, uint64(r.Maxrss) * 1024
}
