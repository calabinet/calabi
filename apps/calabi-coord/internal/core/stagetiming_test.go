package core

import (
	"sync"
	"testing"
	"time"
)

func TestStageTimingsConcurrentAndReset(t *testing.T) {
	var s StageTimings
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				s.Observe(RegisterWait, time.Now().Add(-time.Millisecond))
			}
		}()
	}
	wg.Wait()
	v := s.Snapshot()["register_wait"]
	if v.Count != 2000 || v.Millis < 2000 || v.MaxMillis < 1 {
		t.Fatal(v)
	}
	s.Reset()
	for _, v := range s.Snapshot() {
		if v.Count != 0 || v.Millis != 0 || v.MaxMillis != 0 {
			t.Fatal(v)
		}
	}
}
