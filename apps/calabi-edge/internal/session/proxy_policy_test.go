package session

import (
	"sync"
	"testing"

	"github.com/calabi/calabi/apps/calabi-edge/internal/policy"
)

// TestProxyPolicySwap covers the runtime-swappable security policy that backs
// the config-svc hot-update path: set at registration, atomically swapped on a
// console/SPA edit, read lock-free by listeners. nil load = allow all.
func TestProxyPolicySwap(t *testing.T) {
	p := &Proxy{ID: "p1"}

	// Default: no policy. LoadPolicy is nil and the nil-safe methods allow all.
	if p.LoadPolicy() != nil {
		t.Fatalf("default policy should be nil")
	}
	if p.LoadPolicy().HasIPRules() {
		t.Fatalf("nil policy must report no rules")
	}
	if !p.LoadPolicy().AllowIPString("8.8.8.8") {
		t.Fatalf("nil policy must allow all")
	}

	// Install an allowlist.
	pol, _ := policy.Parse(`{"security":{"ip":{"allow":["203.0.113.0/24"]}}}`)
	p.SetPolicy(pol)
	if !p.LoadPolicy().HasIPRules() {
		t.Fatalf("policy should report rules after set")
	}
	if p.LoadPolicy().AllowIPString("8.8.8.8") {
		t.Fatalf("8.8.8.8 not in allowlist — must be denied")
	}
	if !p.LoadPolicy().AllowIPString("203.0.113.5") {
		t.Fatalf("203.0.113.5 in allowlist — must be allowed")
	}

	// Hot-swap to a different allowlist (the no-reconnect edit).
	pol2, _ := policy.Parse(`{"security":{"ip":{"allow":["8.8.8.0/24"]}}}`)
	p.SetPolicy(pol2)
	if !p.LoadPolicy().AllowIPString("8.8.8.8") {
		t.Fatalf("after swap, 8.8.8.8 must be allowed")
	}
	if p.LoadPolicy().AllowIPString("203.0.113.5") {
		t.Fatalf("after swap, the old allowlist must no longer apply")
	}

	// Clear (empty edit) → back to allow-all.
	p.SetPolicy(nil)
	if p.LoadPolicy() != nil {
		t.Fatalf("policy should be cleared")
	}
	if !p.LoadPolicy().AllowIPString("1.2.3.4") {
		t.Fatalf("cleared policy must allow all")
	}
}

// TestProxyPolicySwap_ConcurrentReadDuringSwap exercises the race detector:
// many readers (listener accepts) load the policy while a writer hot-swaps it.
// Correctness here is just "no torn read / no data race"; values are checked
// in TestProxyPolicySwap.
func TestProxyPolicySwap_ConcurrentReadDuringSwap(t *testing.T) {
	p := &Proxy{ID: "p1"}
	a, _ := policy.Parse(`{"security":{"ip":{"allow":["10.0.0.0/8"]}}}`)
	b, _ := policy.Parse(`{"security":{"ip":{"deny":["10.0.0.0/8"]}}}`)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 2000; j++ {
				_ = p.LoadPolicy().AllowIPString("10.1.2.3")
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 2000; j++ {
			if j%2 == 0 {
				p.SetPolicy(a)
			} else {
				p.SetPolicy(b)
			}
		}
	}()
	wg.Wait()
}
