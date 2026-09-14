// rate_limit_perip_test.go — one visitor must not be able to shed everybody
// else.
//
// THE BUG. A tunnel's rate limit was ONE token bucket shared by every visitor.
// So the control an owner reaches for to keep a tunnel healthy under load is
// also the lever an abuser pulls to take it down: whoever arrives fastest
// drains the bucket, and every legitimate visitor gets 429 until it refills.
// A rate limit that converts one abusive IP into an outage for everyone is a
// self-inflicted denial of service with a checkbox on it.
//
// THE SHAPE OF THE FIX. `per_ip_per_minute` is a SECOND, opt-in bucket keyed by
// visitor address, and the existing tunnel-wide `per_minute` stays exactly as
// it is — the aggregate ceiling. Both must pass. Nothing about an already
// configured tunnel changes meaning, which matters: silently reinterpreting a
// shipped number as per-IP would multiply every existing limit by the number of
// visitors, and nobody would find out until the bill or the upstream did.
//
// RUN: go test./apps/calabi-edge/internal/policy/ -run TestRateLimitPerIP -v
package policy

import (
	"fmt"
	"testing"
)

const perIPCfg = `{"security":{"rate_limit":{"per_minute":600,"per_ip_per_minute":60}}}`

func mustParse(t *testing.T, cfg string) *Policy {
	t.Helper()
	p, err := Parse(cfg)
	if err != nil || p == nil {
		t.Fatalf("parse %s: p=%v err=%v", cfg, p, err)
	}
	return p
}

// The whole point: one address exhausting its own budget leaves another
// address's budget untouched.
func TestRateLimitPerIPIsolatesVisitors(t *testing.T) {
	p := mustParse(t, perIPCfg)

	// Burn the noisy visitor's bucket right down.
	noisy := 0
	for i := 0; i < 200; i++ {
		if p.AllowRate("198.51.100.7") {
			noisy++
		}
	}
	if noisy == 0 || noisy > 60 {
		t.Fatalf("the noisy visitor was admitted %d times; want its own per-IP burst, not none and not everything", noisy)
	}
	if p.AllowRate("198.51.100.7") {
		t.Fatal("the noisy visitor is still being admitted after burning its bucket")
	}

	// The quiet one has not spent anything.
	if !p.AllowRate("203.0.113.9") {
		t.Fatal("a different visitor was shed because somebody else exhausted the tunnel's bucket — " +
			"this is the outage the per-IP bucket exists to prevent")
	}
}

// ...and the tunnel-wide ceiling still holds. Per-IP buckets alone would let N
// visitors multiply the owner's configured cap by N.
func TestRateLimitPerIPKeepsTheTunnelCeiling(t *testing.T) {
	// per_minute 60 (burst 10) is the aggregate; each IP may do 600/min.
	p := mustParse(t, `{"security":{"rate_limit":{"per_minute":60,"per_ip_per_minute":600}}}`)
	allowed := 0
	for i := 0; i < 40; i++ {
		if p.AllowRate(fmt.Sprintf("203.0.113.%d", i)) { // a fresh IP every time
			allowed++
		}
	}
	if allowed > 12 {
		t.Fatalf("%d admitted from 40 distinct addresses; the tunnel-wide cap (burst ~10) "+
			"stopped applying once each visitor got its own bucket", allowed)
	}
}

// Per-IP buckets are a map keyed by attacker-controlled input, so the map is
// the vulnerability. A flood of unique sources must not grow it without bound.
func TestRateLimitPerIPBoundsItsMemory(t *testing.T) {
	p := mustParse(t, perIPCfg)
	for i := 0; i < maxPerIPBuckets*3; i++ {
		p.AllowRate(fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff))
	}
	if n := p.perIPBucketCount(); n > maxPerIPBuckets*2 {
		t.Fatalf("tracking %d addresses after a flood of %d; the cap is %d (two generations)",
			n, maxPerIPBuckets*3, maxPerIPBuckets)
	}
}

// An address we could not read is not a licence to skip the limit. Everything
// unattributable shares one bucket — worse for those visitors than having their
// own, which is the right way round.
func TestRateLimitPerIPUnknownAddressIsStillLimited(t *testing.T) {
	p := mustParse(t, perIPCfg)
	allowed := 0
	for i := 0; i < 200; i++ {
		if p.AllowRate("") {
			allowed++
		}
	}
	if allowed == 0 || allowed > 60 {
		t.Fatalf("unattributable visitors were admitted %d times; want one shared per-IP budget", allowed)
	}
}

// The control: a tunnel that configures only the tunnel-wide limit behaves
// exactly as it did before this existed. Every tunnel in production today is
// this case.
func TestRateLimitPerIPControlTunnelWideOnlyIsUnchanged(t *testing.T) {
	p := mustParse(t, `{"security":{"rate_limit":{"per_minute":60}}}`)
	if p.HasPerIPRateLimit() {
		t.Fatal("a per-IP limit appeared on a tunnel that did not configure one")
	}
	// Same assertion as TestRateLimit, driven through the new signature: burst
	// = 60/6 = 10, refill 1/sec, so a tight loop admits about the burst.
	allowed := 0
	for i := 0; i < 50; i++ {
		if p.AllowRate(fmt.Sprintf("203.0.113.%d", i)) {
			allowed++
		}
	}
	if allowed < 8 || allowed > 12 {
		t.Fatalf("expected ~10 (the tunnel-wide burst) admitted from distinct IPs, got %d", allowed)
	}
}

// A per-IP limit on its own is a complete policy — an owner who wants "no
// single visitor may hammer this" should not have to invent an aggregate too.
func TestRateLimitPerIPAloneIsAPolicy(t *testing.T) {
	p := mustParse(t, `{"security":{"rate_limit":{"per_ip_per_minute":60}}}`)
	if !p.HasPerIPRateLimit() {
		t.Fatal("per_ip_per_minute alone did not produce a per-IP limit")
	}
	burned := 0
	for i := 0; i < 200; i++ {
		if p.AllowRate("198.51.100.7") {
			burned++
		}
	}
	if burned == 0 || burned > 60 {
		t.Fatalf("admitted %d for one address, want its per-IP burst", burned)
	}
	if !p.AllowRate("203.0.113.9") {
		t.Fatal("a second visitor was shed although only a per-IP limit was configured")
	}
}

// The accept path is concurrent: many visitor connections land at once, and
// the bucket map is shared mutable state behind one mutex. Run under -race,
// this is the test that would catch a lock dropped during a refactor — the
// single-goroutine tests above pass happily with no locking at all.
func TestRateLimitPerIPUnderConcurrency(t *testing.T) {
	p := mustParse(t, perIPCfg)
	const goroutines, each = 32, 200
	done := make(chan struct{})
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer func() { done <- struct{}{} }()
			for i := 0; i < each; i++ {
				// A mix: some contention on shared addresses, plus enough
				// distinct ones to force rotations while others are reading.
				p.AllowRate(fmt.Sprintf("203.0.113.%d", i%8))
				p.AllowRate(fmt.Sprintf("10.%d.%d.%d", g, i>>8&0xff, i&0xff))
			}
		}(g)
	}
	for g := 0; g < goroutines; g++ {
		<-done
	}
	if n := p.perIPBucketCount(); n > maxPerIPBuckets*2 {
		t.Fatalf("tracking %d addresses, above the two-generation ceiling %d", n, maxPerIPBuckets*2)
	}
}
