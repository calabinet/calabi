package meshresolver

import (
	"context"
	"errors"
	"testing"
)

type fakeOwners struct {
	out       []Owner
	gen       string
	unchanged bool
	err       error
	// observed inputs, for conditional-poll assertions
	calls     int
	lastKnown string
}

func (f *fakeOwners) ResolveOwners(_ context.Context, _, knownGen string) ([]Owner, string, bool, error) {
	f.calls++
	f.lastKnown = knownGen
	return f.out, f.gen, f.unchanged, f.err
}

type fakeDir struct {
	out []Edge
	err error
}

func (f *fakeDir) ListEdges(context.Context, string) ([]Edge, error) {
	return f.out, f.err
}

func newTestResolver(self int64, owners *fakeOwners, dir *fakeDir) *Resolver {
	return New(Config{
		SelfEdgeID: self,
		Region:     "cn-chengdu",
		BaseDomain: "cn-chengdu.example.com",
		Owners:     owners,
		Dir:        dir,
	})
}

func TestResolveOwnerHappyPath(t *testing.T) {
	owners := &fakeOwners{out: []Owner{
		{Domain: "u1.cn-chengdu.example.com", EdgeNodeID: 200},
	}}
	dir := &fakeDir{out: []Edge{
		{EdgeNodeID: 200, Region: "cn-chengdu", InternalAddr: "10.0.0.200:7090", Healthy: true},
	}}
	r := newTestResolver(100, owners, dir)
	r.refresh(context.Background())

	addr, id, ok := r.ResolveOwner("u1.cn-chengdu.example.com")
	if !ok || addr != "10.0.0.200:7090" || id != 200 {
		t.Fatalf("got (%q,%d,%v), want (10.0.0.200:7090,200,true)", addr, id, ok)
	}
	// Host with a port + uppercase must normalize to the same key.
	addr, _, ok = r.ResolveOwner("U1.CN-CHENGDU.EXAMPLE.COM:443")
	if !ok || addr != "10.0.0.200:7090" {
		t.Fatalf("port/case normalization failed: got (%q,%v)", addr, ok)
	}
}

func TestResolveOwnerSelfIsLocalMiss(t *testing.T) {
	owners := &fakeOwners{out: []Owner{
		{Domain: "u1.cn-chengdu.example.com", EdgeNodeID: 100}, // owner == self
	}}
	dir := &fakeDir{out: []Edge{
		{EdgeNodeID: 100, Region: "cn-chengdu", InternalAddr: "10.0.0.100:7090", Healthy: true},
	}}
	r := newTestResolver(100, owners, dir)
	r.refresh(context.Background())

	if _, _, ok := r.ResolveOwner("u1.cn-chengdu.example.com"); ok {
		t.Fatal("owner == self must be a local miss (ok=false)")
	}
}

func TestResolveOwnerUnknownHost(t *testing.T) {
	r := newTestResolver(100, &fakeOwners{}, &fakeDir{})
	r.refresh(context.Background())
	if _, _, ok := r.ResolveOwner("nope.cn-chengdu.example.com"); ok {
		t.Fatal("unknown host must be ok=false")
	}
}

func TestResolveOwnerDeadOrUnknownPeer(t *testing.T) {
	owners := &fakeOwners{out: []Owner{
		{Domain: "a.cn-chengdu.example.com", EdgeNodeID: 200}, // unhealthy peer
		{Domain: "b.cn-chengdu.example.com", EdgeNodeID: 300}, // peer not in dir
		{Domain: "c.cn-chengdu.example.com", EdgeNodeID: 400}, // peer has no internal_addr
	}}
	dir := &fakeDir{out: []Edge{
		{EdgeNodeID: 200, Region: "cn-chengdu", InternalAddr: "10.0.0.200:7090", Healthy: false},
		{EdgeNodeID: 400, Region: "cn-chengdu", InternalAddr: "", Healthy: true},
	}}
	r := newTestResolver(100, owners, dir)
	r.refresh(context.Background())

	for _, h := range []string{
		"a.cn-chengdu.example.com",
		"b.cn-chengdu.example.com",
		"c.cn-chengdu.example.com",
	} {
		if _, _, ok := r.ResolveOwner(h); ok {
			t.Errorf("%s: dead/unknown/addrless peer must be ok=false", h)
		}
	}
}

func TestResolveOwnerCrossRegionPeerExcluded(t *testing.T) {
	owners := &fakeOwners{out: []Owner{
		{Domain: "x.cn-chengdu.example.com", EdgeNodeID: 900},
	}}
	dir := &fakeDir{out: []Edge{
		// A peer that somehow reports a different region: never forwarded to.
		{EdgeNodeID: 900, Region: "cn-hangzhou", InternalAddr: "10.1.0.900:7090", Healthy: true},
	}}
	r := newTestResolver(100, owners, dir)
	r.refresh(context.Background())
	if _, _, ok := r.ResolveOwner("x.cn-chengdu.example.com"); ok {
		t.Fatal("cross-region peer must never be a forward target")
	}
}

func TestRefreshKeepsStaleCacheOnError(t *testing.T) {
	owners := &fakeOwners{out: []Owner{
		{Domain: "u1.cn-chengdu.example.com", EdgeNodeID: 200},
	}}
	dir := &fakeDir{out: []Edge{
		{EdgeNodeID: 200, Region: "cn-chengdu", InternalAddr: "10.0.0.200:7090", Healthy: true},
	}}
	r := newTestResolver(100, owners, dir)
	r.refresh(context.Background())
	if _, _, ok := r.ResolveOwner("u1.cn-chengdu.example.com"); !ok {
		t.Fatal("precondition: should resolve before error")
	}

	// Both sources now error — the cache must NOT be blanked.
	owners.err = errors.New("transport blip")
	dir.err = errors.New("transport blip")
	r.refresh(context.Background())
	if _, _, ok := r.ResolveOwner("u1.cn-chengdu.example.com"); !ok {
		t.Fatal("stale cache should survive a refresh error")
	}
}

func TestUnsupportedTransportDetection(t *testing.T) {
	if !isUnsupported(errors.New("tunnelstore: ResolveOwners not supported by this transport")) {
		t.Error("should detect ResolveOwners unsupported sentinel")
	}
	if !isUnsupported(errors.New("identity: ListEdges not supported by this transport")) {
		t.Error("should detect ListEdges unsupported sentinel")
	}
	if isUnsupported(errors.New("connection refused")) {
		t.Error("transient errors must not be treated as unsupported")
	}
}

func TestRefreshSoonNonBlocking(t *testing.T) {
	r := newTestResolver(100, &fakeOwners{}, &fakeDir{})
	// Fill the kick buffer then call again — must not block or panic.
	r.RefreshSoon()
	r.RefreshSoon()
	if len(r.kick) != 1 {
		t.Fatalf("kick buffer = %d, want 1 (coalesced)", len(r.kick))
	}
}

// TestConditionalPollThreadsGenerationAndKeepsCache exercises the ETag-style
// conditional poll: the first refresh sends an empty known_generation and
// applies the snapshot; a follow-up that reports unchanged must NOT blank the
// cache and must have echoed back the generation we last saw.
func TestConditionalPollThreadsGenerationAndKeepsCache(t *testing.T) {
	owners := &fakeOwners{
		out: []Owner{{Domain: "u1.cn-chengdu.example.com", EdgeNodeID: 200}},
		gen: "G1",
	}
	dir := &fakeDir{out: []Edge{
		{EdgeNodeID: 200, Region: "cn-chengdu", InternalAddr: "10.0.0.200:7090", Healthy: true},
	}}
	r := newTestResolver(100, owners, dir)

	// First poll: known_generation is empty, full snapshot applied.
	r.refresh(context.Background())
	if owners.lastKnown != "" {
		t.Fatalf("first poll should send empty known_generation, got %q", owners.lastKnown)
	}
	if _, _, ok := r.ResolveOwner("u1.cn-chengdu.example.com"); !ok {
		t.Fatal("precondition: owner should resolve after first poll")
	}
	if r.lastOwnerGen != "G1" {
		t.Fatalf("resolver should have stored generation G1, got %q", r.lastOwnerGen)
	}

	// Second poll: server says unchanged with no items. The cache must
	// survive and we must have sent our cached generation back.
	owners.out = nil
	owners.unchanged = true
	r.refresh(context.Background())
	if owners.lastKnown != "G1" {
		t.Fatalf("second poll should echo back known_generation G1, got %q", owners.lastKnown)
	}
	if _, _, ok := r.ResolveOwner("u1.cn-chengdu.example.com"); !ok {
		t.Fatal("unchanged poll must NOT blank the owner cache")
	}

	// A subsequent CHANGED poll (new generation, new set) must replace it.
	owners.unchanged = false
	owners.gen = "G2"
	owners.out = []Owner{{Domain: "u9.cn-chengdu.example.com", EdgeNodeID: 200}}
	r.refresh(context.Background())
	if r.lastOwnerGen != "G2" {
		t.Fatalf("changed poll should advance generation to G2, got %q", r.lastOwnerGen)
	}
	if _, _, ok := r.ResolveOwner("u1.cn-chengdu.example.com"); ok {
		t.Fatal("old owner should be gone after a changed snapshot")
	}
	if _, _, ok := r.ResolveOwner("u9.cn-chengdu.example.com"); !ok {
		t.Fatal("new owner should resolve after a changed snapshot")
	}
}
