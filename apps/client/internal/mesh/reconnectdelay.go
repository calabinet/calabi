package mesh

import (
	"math/rand/v2"
	"time"
)

// ReconnectDelay spreads retries around the existing exponential backoff.
// This random value only schedules work; it is not a token or security nonce.
// Callers must retain their cancellation and network-change wakeup paths.
// The actual wait is 75–125% of base (up to 75s for a 60s base).
func ReconnectDelay(base time.Duration) time.Duration {
	return reconnectDelay(base, rand.Int64N)
}

func reconnectDelay(base time.Duration, random func(int64) int64) time.Duration {
	if base <= 0 {
		return 0
	}
	return base*3/4 + time.Duration(random(int64(base/2)+1))
}
