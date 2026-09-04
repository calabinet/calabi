package core

import (
	"context"
	"errors"
	"testing"
)

func relayCoord(t *testing.T) (*Coordinator, context.Context) {
	t.Helper()
	c := newTestCoord()
	relays := NewMemRelayStore()
	c.Relays = relays
	// The map every org actually receives: platform regions plus its own.
	c.DERP = CompositeDERP{
		Platform: DERPMap{Regions: []DERPRegion{region("lax")}},
		Relays:   relays,
	}
	return c, context.Background()
}

func mustRegister(t *testing.T, c *Coordinator, ctx context.Context, meshnet MeshnetID, label, host string) *Relay {
	t.Helper()
	r, err := c.RegisterRelay(ctx, meshnet, Relay{Label: label, HostName: host, DERPPort: 3340})
	if err != nil {
		t.Fatalf("register %q: %v", label, err)
	}
	return r
}

// UpsertRelay is idempotent by label (edge/derp merge-B): same data →
// changed=false (no netmap churn on a heartbeat); changed host → update in place;
// new label → create. This is what lets a merged node self-register every 30s.
func TestUpsertRelay_Idempotent(t *testing.T) {
	c, ctx := relayCoord(t)

	r1, changed, err := c.UpsertRelay(ctx, 1, Relay{Label: "hk", HostName: "h1.example", DERPPort: 3340})
	if err != nil || !changed {
		t.Fatalf("create: changed=%v err=%v", changed, err)
	}
	if _, changed, err := c.UpsertRelay(ctx, 1, Relay{Label: "hk", HostName: "h1.example", DERPPort: 3340}); err != nil || changed {
		t.Fatalf("no-op re-register: changed=%v err=%v (want changed=false)", changed, err)
	}
	r2, changed, err := c.UpsertRelay(ctx, 1, Relay{Label: "hk", HostName: "h2.example", DERPPort: 3340})
	if err != nil || !changed {
		t.Fatalf("update host: changed=%v err=%v", changed, err)
	}
	if r2.ID != r1.ID {
		t.Errorf("update created a new relay (id %d→%d) instead of rewriting", r1.ID, r2.ID)
	}
	if r2.HostName != "h2.example" {
		t.Errorf("host not updated: %q", r2.HostName)
	}
	if list, _ := c.RelaysFor(ctx, 1); len(list) != 1 {
		t.Fatalf("org has %d relays, want 1 (upsert must not duplicate)", len(list))
	}
	if _, changed, err := c.UpsertRelay(ctx, 1, Relay{Label: "sg", HostName: "h3.example", DERPPort: 3340}); err != nil || !changed {
		t.Fatalf("new label: changed=%v err=%v", changed, err)
	}
	if list, _ := c.RelaysFor(ctx, 1); len(list) != 2 {
		t.Fatalf("after new label: %d relays, want 2", len(list))
	}
}

// One machine (host) runs one relay: when a node self-registers the SAME host
// under a NEW label (the operator renamed the region — e.g. dropping an explicit
// relay.label so it falls back to the node's region), the stale row is retired
// rather than left as an orphan region pointing at the same box. A different host
// is never touched.
func TestUpsertRelay_RetiresHostReregisteredUnderNewLabel(t *testing.T) {
	c, ctx := relayCoord(t)

	// Node first self-registers under label "hk1" on host h1.
	if _, changed, err := c.UpsertRelay(ctx, 1, Relay{Label: "hk1", HostName: "h1.example", DERPPort: 3350}); err != nil || !changed {
		t.Fatalf("initial register: changed=%v err=%v", changed, err)
	}
	// An UNRELATED host in the same org — must survive the retirement below.
	if _, _, err := c.UpsertRelay(ctx, 1, Relay{Label: "other", HostName: "h2.example", DERPPort: 3340}); err != nil {
		t.Fatalf("other-host register: %v", err)
	}

	// Same host h1, NEW label "my-vps-hk" (region rename). The stale self-hk1 must
	// be retired, and the map change must be reported (changed=true).
	r, changed, err := c.UpsertRelay(ctx, 1, Relay{Label: "my-vps-hk", HostName: "h1.example", DERPPort: 3350})
	if err != nil || !changed {
		t.Fatalf("re-register new label: changed=%v err=%v", changed, err)
	}
	if r.RegionCode() != "self-my-vps-hk" {
		t.Errorf("new region = %q, want self-my-vps-hk", r.RegionCode())
	}

	list, _ := c.RelaysFor(ctx, 1)
	labels := map[string]bool{}
	for _, rl := range list {
		labels[rl.Label] = true
	}
	if labels["hk1"] {
		t.Error("stale self-hk1 was not retired after the host re-registered under a new label")
	}
	if !labels["my-vps-hk"] || !labels["other"] {
		t.Errorf("expected {my-vps-hk, other}, got %v", labels)
	}
	if len(list) != 2 {
		t.Fatalf("org has %d relays, want 2 (retired hk1, kept my-vps-hk + other)", len(list))
	}

	// A steady-state heartbeat (same label, same host) now retires nothing and
	// must report changed=false — no netmap churn.
	if _, changed, err := c.UpsertRelay(ctx, 1, Relay{Label: "my-vps-hk", HostName: "h1.example", DERPPort: 3350}); err != nil || changed {
		t.Fatalf("steady-state after retirement: changed=%v err=%v (want changed=false)", changed, err)
	}
}

// Constraint ①: a relay sees no plaintext but it does see who talks to whom,
// how much and when. One org's relay in another's map hands its operator that
// picture of a stranger's traffic.
func TestARelayOnlyAppearsInItsOwnOrgsMap(t *testing.T) {
	c, ctx := relayCoord(t)
	mustRegister(t, c, ctx, 1, "tokyo", "relay1.example")

	mine, err := c.DERP.DERPMap(ctx, 1)
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if !mine.HasRegion("self-tokyo") {
		t.Fatal("the org's own relay is missing from its map")
	}
	theirs, err := c.DERP.DERPMap(ctx, 2)
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if theirs.HasRegion("self-tokyo") {
		t.Fatal("one org's relay leaked into another's map")
	}
}

// Constraint ②: self-hosting adds a nearer road, it does not replace the road.
// A user's VPS going down must not leave the meshnet with only direct paths —
// and DefaultDERPHome names a platform region, so dropping them would also
// leave new nodes with an unresolvable home.
func TestPlatformRegionsSurviveEverything(t *testing.T) {
	c, ctx := relayCoord(t)
	r := mustRegister(t, c, ctx, 1, "tokyo", "relay1.example")

	for _, step := range []struct {
		name string
		do   func()
	}{
		{"after registering", func() {}},
		{"after parking the relay", func() {
			if _, err := c.SetRelayEnabled(ctx, 1, r.ID, false); err != nil {
				t.Fatalf("park: %v", err)
			}
		}},
		{"after deleting it", func() {
			if err := c.DeleteRelay(ctx, 1, r.ID); err != nil {
				t.Fatalf("delete: %v", err)
			}
		}},
	} {
		step.do()
		m, err := c.DERP.DERPMap(ctx, 1)
		if err != nil {
			t.Fatalf("%s: map: %v", step.name, err)
		}
		if !m.HasRegion("lax") {
			t.Fatalf("%s: the platform region vanished", step.name)
		}
	}
}

// A parked relay keeps its registration but leaves the map, so an operator can
// take a machine down for maintenance without re-registering it afterwards.
func TestParkedRelayLeavesTheMapButKeepsItsRegistration(t *testing.T) {
	c, ctx := relayCoord(t)
	r := mustRegister(t, c, ctx, 1, "tokyo", "relay1.example")

	if _, err := c.SetRelayEnabled(ctx, 1, r.ID, false); err != nil {
		t.Fatalf("park: %v", err)
	}
	m, _ := c.DERP.DERPMap(ctx, 1)
	if m.HasRegion("self-tokyo") {
		t.Error("a parked relay is still in the map")
	}
	list, err := c.RelaysFor(ctx, 1)
	if err != nil || len(list) != 1 {
		t.Fatalf("registration was lost: %v (%d rows)", err, len(list))
	}

	if _, err := c.SetRelayEnabled(ctx, 1, r.ID, true); err != nil {
		t.Fatalf("un-park: %v", err)
	}
	if m, _ := c.DERP.DERPMap(ctx, 1); !m.HasRegion("self-tokyo") {
		t.Error("un-parking did not put it back in the map")
	}
}

// Constraint ③: the region code is the key nodes report a home under and the
// relay pool dials by. A user's label must not be able to mean the platform's
// region — hence the prefix, and hence the check that the prefixed code isn't
// already published.
func TestRegionCodesAreNamespaced(t *testing.T) {
	c, ctx := relayCoord(t)
	r := mustRegister(t, c, ctx, 1, "lax", "relay1.example")
	if r.RegionCode() != "self-lax" {
		t.Fatalf("region code = %q, want self-lax", r.RegionCode())
	}
	m, _ := c.DERP.DERPMap(ctx, 1)
	if !m.HasRegion("lax") || !m.HasRegion("self-lax") {
		t.Fatal("a label matching a platform region should coexist with it, namespaced")
	}
}

func TestRegisterRejectsAShadowingLabel(t *testing.T) {
	c, ctx := relayCoord(t)
	// A platform region literally named "self-x" is the only way a registration
	// could collide; guard it rather than assume the platform never does that.
	c.DERP = CompositeDERP{
		Platform: DERPMap{Regions: []DERPRegion{region("lax"), region("self-taken")}},
		Relays:   c.Relays,
	}
	_, err := c.RegisterRelay(ctx, 1, Relay{Label: "taken", HostName: "h.example", DERPPort: 3340})
	if !errors.Is(err, ErrInvalidRelay) {
		t.Fatalf("err = %v, want ErrInvalidRelay for a label that shadows a platform region", err)
	}
}

func TestRegisterValidation(t *testing.T) {
	c, ctx := relayCoord(t)
	for name, in := range map[string]Relay{
		"empty label":    {Label: "", HostName: "h.example", DERPPort: 3340},
		"bad label":      {Label: "Tokyo Relay!", HostName: "h.example", DERPPort: 3340},
		"empty host":     {Label: "tokyo", HostName: "  ", DERPPort: 3340},
		"no derp port":   {Label: "tokyo", HostName: "h.example"},
		"port too large": {Label: "tokyo", HostName: "h.example", DERPPort: 70000},
	} {
		if _, err := c.RegisterRelay(ctx, 1, in); !errors.Is(err, ErrInvalidRelay) {
			t.Errorf("%s: err = %v, want ErrInvalidRelay", name, err)
		}
	}
	// A registration with no STUN port gets the default rather than a rejection:
	// a region that can't be latency-measured is never chosen as a home, so
	// omitting it would silently register a relay that does nothing.
	r, err := c.RegisterRelay(ctx, 1, Relay{Label: "tokyo", HostName: "h.example", DERPPort: 3340})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if r.STUNPort != defaultRelaySTUNPort {
		t.Errorf("stun port = %d, want the default %d", r.STUNPort, defaultRelaySTUNPort)
	}
	if _, err := c.RegisterRelay(ctx, 1, Relay{Label: "tokyo", HostName: "other.example", DERPPort: 3340}); !errors.Is(err, ErrRelayExists) {
		t.Errorf("duplicate label was accepted")
	}
}

// A relay id from another tenant is NOT FOUND, never someone else's row — and
// not a different error either, which would confirm the row exists.
func TestRelayMutationsAreScopedToTheCallersMeshnet(t *testing.T) {
	c, ctx := relayCoord(t)
	theirs := mustRegister(t, c, ctx, 2, "tokyo", "relay1.example")

	if _, err := c.SetRelayEnabled(ctx, 1, theirs.ID, false); !errors.Is(err, ErrRelayNotFound) {
		t.Errorf("park across tenants: err = %v, want ErrRelayNotFound", err)
	}
	if err := c.DeleteRelay(ctx, 1, theirs.ID); !errors.Is(err, ErrRelayNotFound) {
		t.Errorf("delete across tenants: err = %v, want ErrRelayNotFound", err)
	}
	if list, _ := c.RelaysFor(ctx, 2); len(list) != 1 || !list[0].Enabled {
		t.Error("another tenant's relay was modified")
	}
}

func TestRelayCap(t *testing.T) {
	c, ctx := relayCoord(t)
	for i := 0; i < maxRelaysPerMeshnet; i++ {
		mustRegister(t, c, ctx, 1, "r"+string(rune('a'+i)), "h.example")
	}
	_, err := c.RegisterRelay(ctx, 1, Relay{Label: "onemore", HostName: "h.example", DERPPort: 3340})
	if !errors.Is(err, ErrTooManyRelays) {
		t.Fatalf("err = %v, want ErrTooManyRelays", err)
	}
}

// A registry failure must not cost the org the PLATFORM's relays as well; that
// would turn "my own relay is unavailable" into "my mesh has no fallback".
func TestMapDegradesToPlatformWhenTheRegistryFails(t *testing.T) {
	src := CompositeDERP{
		Platform: DERPMap{Regions: []DERPRegion{region("lax")}},
		Relays:   brokenRelayStore{},
	}
	m, err := src.DERPMap(context.Background(), 1)
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if !m.HasRegion("lax") {
		t.Fatal("a registry failure took the platform regions with it")
	}
}

type brokenRelayStore struct{}

func (brokenRelayStore) ListRelays(context.Context, MeshnetID) ([]Relay, error) {
	return nil, errors.New("registry is down")
}
func (brokenRelayStore) CreateRelay(context.Context, Relay) (*Relay, error) { return nil, nil }
func (brokenRelayStore) UpdateRelay(context.Context, Relay) error           { return nil }
func (brokenRelayStore) DeleteRelay(context.Context, int64) error           { return nil }
