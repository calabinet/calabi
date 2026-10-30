package mesh

import (
	"sort"
	"sync"
	"testing"
	"time"
)

func fleetQuantiles(samples []float64) map[string]float64 {
	v := append([]float64(nil), samples...)
	sort.Float64s(v)
	if len(v) == 0 {
		return nil
	}
	out := map[string]float64{"count": float64(len(v))}
	for _, p := range []int{50, 95, 99, 100} {
		key := map[int]string{50: "p50_ms", 95: "p95_ms", 99: "p99_ms", 100: "max_ms"}[p]
		out[key] = v[(len(v)*p+99)/100-1]
	}
	return out
}

type fleetClientTimings struct {
	mu      sync.Mutex
	samples map[string][]float64
}

func (s *fleetClientTimings) observe(name string, start time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.samples == nil {
		s.samples = map[string][]float64{}
	}
	s.samples[name] = append(s.samples[name], float64(time.Since(start))/float64(time.Millisecond))
}
func (s *fleetClientTimings) snapshot() map[string]map[string]float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]map[string]float64{}
	for k, v := range s.samples {
		out[k] = fleetQuantiles(v)
		var total float64
		for _, n := range v {
			total += n
		}
		out[k]["total_ms"] = total
	}
	return out
}

func TestFleetRecoveryQuantiles(t *testing.T) {
	v := make([]float64, 1000)
	for i := range v {
		v[i] = float64(1000 - i)
	}
	q := fleetQuantiles(v)
	if q["p50_ms"] != 500 || q["p95_ms"] != 950 || q["p99_ms"] != 990 || q["max_ms"] != 1000 || v[0] != 1000 {
		t.Fatal(q)
	}
	if fleetQuantiles(nil) != nil {
		t.Fatal("empty observations fabricated")
	}
}
