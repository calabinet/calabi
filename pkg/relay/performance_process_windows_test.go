package relay

import (
	"syscall"
	"unsafe"
)

func performanceProcessUsage() (float64, uint64) {
	h, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0, 0
	}
	var created, exited, kernel, user syscall.Filetime
	_ = syscall.GetProcessTimes(h, &created, &exited, &kernel, &user)
	toSeconds := func(t syscall.Filetime) float64 {
		return float64(uint64(t.HighDateTime)<<32|uint64(t.LowDateTime)) / 1e7
	}
	type memoryCounters struct {
		Size, Faults                                                                    uint32
		Peak, Working, PeakPaged, Paged, PeakNonPaged, NonPaged, Pagefile, PeakPagefile uintptr
	}
	m := memoryCounters{}
	m.Size = uint32(unsafe.Sizeof(m))
	proc := syscall.NewLazyDLL("psapi.dll").NewProc("GetProcessMemoryInfo")
	_, _, _ = proc.Call(uintptr(h), uintptr(unsafe.Pointer(&m)), uintptr(m.Size))
	return toSeconds(kernel) + toSeconds(user), uint64(m.Peak)
}
