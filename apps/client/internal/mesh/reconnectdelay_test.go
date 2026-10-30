package mesh

import (
	"math/rand/v2"
	"testing"
	"time"
)

func TestReconnectDelayBoundsAndSpread(t *testing.T) {
	for _, base := range []time.Duration{0, -time.Second, time.Second, 2 * time.Second, 30 * time.Second, time.Minute} {
		r := rand.New(rand.NewPCG(4, 7))
		seen := map[time.Duration]bool{}
		for i := 0; i < 1000; i++ {
			d := reconnectDelay(base, r.Int64N)
			if base <= 0 {
				if d != 0 {
					t.Fatal("nonpositive delay must not wait")
				}
				continue
			}
			if d < base*3/4 || d > base*5/4 {
				t.Fatalf("delay %v outside bounds for %v", d, base)
			}
			seen[d] = true
		}
		if base > 0 && len(seen) < 900 {
			t.Fatal("retries remain synchronized")
		}
	}
}
