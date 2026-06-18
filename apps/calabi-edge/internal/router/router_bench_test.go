package router

import (
	"fmt"
	"math/rand"
	"sync/atomic"
	"testing"
)

// BenchmarkRouter_LookupHTTP is the hot-path microbench for the
// per-visitor HTTP route resolution. Targets:
//   - 1k registered tunnels: lookup < 200ns/op, 0 allocs
//   - parallel (GOMAXPROCS=8): no measurable contention (RWMutex)
//
// Run via: go test -bench=Router -benchmem./apps/calabi-edge/internal/router/...
func BenchmarkRouter_LookupHTTP(b *testing.B) {
	for _, n := range []int{1, 10, 100, 1000, 10000} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			r := New()
			domains := make([]string, n)
			for i := 0; i < n; i++ {
				domains[i] = fmt.Sprintf("tunnel-%06d.localtest.me", i)
				if err := r.RegisterHTTP(domains[i], nil, "sess", fmt.Sprintf("p%d", i)); err != nil {
					b.Fatalf("register: %v", err)
				}
			}
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, ok := r.LookupHTTP(domains[i%n]); !ok {
					b.Fatalf("lookup miss for %s", domains[i%n])
				}
			}
		})
	}
}

// BenchmarkRouter_LookupHTTP_Parallel exercises RWMutex read contention
// with N goroutines doing lookups against a fixed table size.
func BenchmarkRouter_LookupHTTP_Parallel(b *testing.B) {
	const n = 1000
	r := New()
	domains := make([]string, n)
	for i := 0; i < n; i++ {
		domains[i] = fmt.Sprintf("tunnel-%06d.localtest.me", i)
		_ = r.RegisterHTTP(domains[i], nil, "sess", fmt.Sprintf("p%d", i))
	}
	b.ResetTimer()
	b.ReportAllocs()
	var hits atomic.Uint64
	b.RunParallel(func(pb *testing.PB) {
		// Each goroutine has its own random sequence to avoid lockstep.
		rng := rand.New(rand.NewSource(rand.Int63()))
		for pb.Next() {
			if _, ok := r.LookupHTTP(domains[rng.Intn(n)]); ok {
				hits.Add(1)
			}
		}
	})
	if hits.Load() == 0 {
		b.Fatalf("parallel lookups produced 0 hits")
	}
}

// BenchmarkRouter_LookupTCP covers the same hot path for TCP tunnels
// where the key is a uint32 port rather than a string. Should be even
// faster than the HTTP variant (no string hashing).
func BenchmarkRouter_LookupTCP(b *testing.B) {
	const n = 1000
	r := New()
	for i := 0; i < n; i++ {
		port := uint32(20000 + i)
		_ = r.RegisterTCP(port, nil, "sess", fmt.Sprintf("p%d", i))
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		port := uint32(20000 + (i % n))
		if _, ok := r.LookupTCP(port); !ok {
			b.Fatalf("lookup miss for :%d", port)
		}
	}
}

// BenchmarkRouter_MixedRegisterLookup represents the steady-state hot
// path where new tunnels register while visitors lookup -- the realistic
// "1000 visitors, 5 tunnels/sec churning" shape. We do 100 lookups per
// register call to mirror real traffic ratios.
func BenchmarkRouter_MixedRegisterLookup(b *testing.B) {
	const initial = 1000
	r := New()
	for i := 0; i < initial; i++ {
		_ = r.RegisterHTTP(fmt.Sprintf("tunnel-%06d.localtest.me", i), nil, "sess", fmt.Sprintf("p%d", i))
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// 1 register
		domain := fmt.Sprintf("new-%06d.localtest.me", i)
		proxyID := fmt.Sprintf("np%d", i)
		_ = r.RegisterHTTP(domain, nil, "sess", proxyID)
		// 100 lookups against the steady set
		for j := 0; j < 100; j++ {
			_, _ = r.LookupHTTP(fmt.Sprintf("tunnel-%06d.localtest.me", j))
		}
		// Cleanup so the table doesn't grow unbounded across iterations.
		r.UnregisterByProxyID(proxyID)
	}
}
