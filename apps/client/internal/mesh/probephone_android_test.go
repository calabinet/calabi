package mesh

import (
	"os"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Run by adb on an actual Android device. This exercises native WireGuard,
// UDP and the relay with an in-memory TUN; it does not measure VpnService
// lifecycle, radio energy or EMUI's treatment of an installed app.
func TestProbeAndroidIdleAndResume(t *testing.T) {
	if os.Getenv("CALABI_TEST_PHONE_SOAK") != "1" {
		t.Skip("set CALABI_TEST_PHONE_SOAK=1 on an Android device")
	}
	pair := newProbeBusinessPairAtRate(t, true, 20)
	defer pair.cleanup()
	for i := 0; i < 10; i++ {
		pair.transmit(t)
	}
	t.Log("phone core ready; waiting for activity expiry (screen may be switched off)")
	time.Sleep(70 * time.Second)
	s := pair.probers[0].scheduler
	beforeSent, beforeRuns := s.sent.Load(), s.runs.Load()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	beforeTasks := runtime.NumGoroutine()
	var cpuBefore, cpuAfter unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &cpuBefore); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Second)
	if s.sent.Load() != beforeSent || s.runs.Load()-beforeRuns > 2 {
		t.Fatalf("idle core kept probing: sent %d -> %d, scheduler turns=%d", beforeSent, s.sent.Load(), s.runs.Load()-beforeRuns)
	}
	if err := unix.Getrusage(unix.RUSAGE_SELF, &cpuAfter); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	afterTasks := runtime.NumGoroutine()
	if after.HeapAlloc > before.HeapAlloc+2<<20 || afterTasks > beforeTasks+2 {
		t.Fatalf("idle resources grew: heap %d -> %d, goroutines %d -> %d", before.HeapAlloc, after.HeapAlloc, beforeTasks, afterTasks)
	}
	cpu := func(v unix.Rusage) float64 {
		return float64(v.Utime.Sec+v.Stime.Sec) + float64(v.Utime.Usec+v.Stime.Usec)/1e6
	}
	t.Logf("idle_seconds=30 ping_delta=%d scheduler_turns=%d heap=%d->%d goroutines=%d->%d cpu_seconds=%.6f", s.sent.Load()-beforeSent, s.runs.Load()-beforeRuns, before.HeapAlloc, after.HeapAlloc, beforeTasks, afterTasks, cpu(cpuAfter)-cpu(cpuBefore))
	latency := pair.transmit(t)
	t.Logf("resume_delivery=%s", latency)
}
