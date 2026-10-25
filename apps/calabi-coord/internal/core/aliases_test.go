package core

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"testing"
)

func prefixes(t *testing.T, ss ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, pfx(t, s))
	}
	return out
}

// An alias needs BOTH halves: the node asked, and an admin approved. Either one
// missing and the route publishes under its real CIDR.
func TestReconcileAliasesNeedsRequestAndApproval(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name              string
		approved, request []string
		wantAliased       []string
	}{
		{"asked and approved", []string{"192.168.1.0/24"}, []string{"192.168.1.0/24"}, []string{"192.168.1.0/24"}},
		{"asked but not approved", nil, []string{"192.168.1.0/24"}, nil},
		{"approved but not asked", []string{"192.168.1.0/24"}, nil, nil},
		{"one of two", []string{"192.168.1.0/24", "10.0.0.0/24"}, []string{"10.0.0.0/24"}, []string{"10.0.0.0/24"}},
		{"an unmasked request still matches", []string{"192.168.1.0/24"}, []string{"192.168.1.7/24"}, []string{"192.168.1.0/24"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := &Node{
				ApprovedRoutes: prefixes(t, c.approved...),
				AliasedRoutes:  prefixes(t, c.request...),
			}
			keep, _, err := reconcileAliases(ctx, NewMemAliasIPAM(), MeshnetID(1), n, math.MaxInt)
			if err != nil {
				t.Fatal(err)
			}
			if len(keep) != len(c.wantAliased) {
				t.Fatalf("aliased %v, want %v", keep, c.wantAliased)
			}
			for i, want := range c.wantAliased {
				if keep[i].Real != pfx(t, want) {
					t.Errorf("aliased[%d].Real = %s, want %s", i, keep[i].Real, want)
				}
				if keep[i].Alias.Bits() != keep[i].Real.Bits() {
					t.Errorf("alias %s is not the same size as %s", keep[i].Alias, keep[i].Real)
				}
			}
		})
	}
}

// An alias is an address consumers hold routes for. Re-drawing one because the
// daemon restarted would move a working subnet out from under them.
func TestReconcileAliasesIsStableAcrossReRegistration(t *testing.T) {
	ctx := context.Background()
	pool := NewMemAliasIPAM()
	n := &Node{
		ApprovedRoutes: prefixes(t, "192.168.1.0/24"),
		AliasedRoutes:  prefixes(t, "192.168.1.0/24"),
	}
	first, _, err := reconcileAliases(ctx, pool, MeshnetID(1), n, math.MaxInt)
	if err != nil {
		t.Fatal(err)
	}
	n.RouteAliases = first

	for i := 0; i < 5; i++ {
		again, release, err := reconcileAliases(ctx, pool, MeshnetID(1), n, math.MaxInt)
		if err != nil {
			t.Fatal(err)
		}
		if len(release) != 0 {
			t.Fatalf("re-registration released %v", release)
		}
		if len(again) != 1 || again[0] != first[0] {
			t.Fatalf("alias moved on re-registration: %v, was %v", again, first)
		}
		n.RouteAliases = again
	}
}

// Losing either half hands the block back, or the pool leaks blocks nobody can
// reach until the next restart.
func TestReconcileAliasesReleasesWhenEitherHalfGoesAway(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name  string
		strip func(*Node)
	}{
		{"admin withdraws approval", func(n *Node) { n.ApprovedRoutes = nil }},
		{"node stops asking", func(n *Node) { n.AliasedRoutes = nil }},
	} {
		t.Run(c.name, func(t *testing.T) {
			pool := NewMemAliasIPAM()
			n := &Node{
				ApprovedRoutes: prefixes(t, "192.168.1.0/24"),
				AliasedRoutes:  prefixes(t, "192.168.1.0/24"),
			}
			held, _, err := reconcileAliases(ctx, pool, MeshnetID(1), n, math.MaxInt)
			if err != nil || len(held) != 1 {
				t.Fatalf("setup: %v %v", held, err)
			}
			n.RouteAliases = held

			c.strip(n)
			keep, release, err := reconcileAliases(ctx, pool, MeshnetID(1), n, math.MaxInt)
			if err != nil {
				t.Fatal(err)
			}
			if len(keep) != 0 {
				t.Errorf("kept %v, want none", keep)
			}
			if len(release) != 1 || release[0] != held[0].Alias {
				t.Fatalf("released %v, want [%s]", release, held[0].Alias)
			}
		})
	}
}

// A coordinator with no alias allocator is the pre-feature coordinator: nothing
// is granted, and anything held is handed back.
func TestReconcileAliasesWithoutAPoolGrantsNothing(t *testing.T) {
	n := &Node{
		ApprovedRoutes: prefixes(t, "192.168.1.0/24"),
		AliasedRoutes:  prefixes(t, "192.168.1.0/24"),
		RouteAliases:   []RouteAlias{{Real: pfx(t, "10.0.0.0/24"), Alias: pfx(t, "100.96.0.0/24")}},
	}
	keep, release, err := reconcileAliases(context.Background(), nil, MeshnetID(1), n, math.MaxInt)
	if err != nil {
		t.Fatal(err)
	}
	if len(keep) != 0 {
		t.Errorf("granted %v with no pool", keep)
	}
	if len(release) != 1 {
		t.Errorf("released %v, want the one it held", release)
	}
}

// What peers are told: the alias where there is one, the real CIDR otherwise.
// Consumers must never learn the real CIDR of an aliased route — that is the
// address that collides with their own LAN, which is the whole point.
func TestPublishedRoutesSubstitutesAliases(t *testing.T) {
	n := &Node{
		ApprovedRoutes: prefixes(t, "192.168.1.0/24", "10.9.0.0/16"),
		RouteAliases:   []RouteAlias{{Real: pfx(t, "192.168.1.0/24"), Alias: pfx(t, "100.96.5.0/24")}},
	}
	got := PublishedRoutes(n)
	want := prefixes(t, "100.96.5.0/24", "10.9.0.0/16")
	if len(got) != len(want) {
		t.Fatalf("published %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("published[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}

// End to end through the coordinator: a node that registers asking for an alias
// gets one, its peers are told the alias, and withdrawing approval hands the
// block back — the three transitions that decide whether the pool leaks.
func TestCoordinatorAllocatesAndReleasesSubnetAliases(t *testing.T) {
	ctx := context.Background()
	c := newTestCoord()
	c.AutoApproveAllRoutes = true // aliases follow approval; how routes get approved is not this test's subject
	pool := NewMemAliasIPAM()
	c.AliasIPAM = pool

	lan := pfx(t, "192.168.1.0/24")
	node, err := c.Register(ctx, RegisterInput{
		Meshnet:          MeshnetID(1),
		Name:             "router",
		NodeKey:          key(1),
		AdvertisedRoutes: []netip.Prefix{lan},
		AliasedRoutes:    []netip.Prefix{lan},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(node.RouteAliases) != 1 || node.RouteAliases[0].Real != lan {
		t.Fatalf("register: aliases %v, want one for %s", node.RouteAliases, lan)
	}
	alias := node.RouteAliases[0].Alias
	if !overlayAliasPool.Contains(alias.Addr()) || alias.Bits() != lan.Bits() {
		t.Fatalf("alias %s is not a same-size block from %s", alias, overlayAliasPool)
	}

	// Peers are told the alias and never the real CIDR.
	pub := PublishedRoutes(node)
	if len(pub) != 1 || pub[0] != alias {
		t.Fatalf("published %v, want [%s]", pub, alias)
	}

	// Re-registering must not move it (consumers hold routes for it).
	again, err := c.Register(ctx, RegisterInput{
		Meshnet:          MeshnetID(1),
		Name:             "router",
		NodeKey:          key(1),
		AdvertisedRoutes: []netip.Prefix{lan},
		AliasedRoutes:    []netip.Prefix{lan},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(again.RouteAliases) != 1 || again.RouteAliases[0].Alias != alias {
		t.Fatalf("re-register moved the alias: %v, was %s", again.RouteAliases, alias)
	}

	// Withdrawing approval releases the block AND persists the empty set.
	reviewed, err := c.ApproveRoutes(ctx, MeshnetID(1), again.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(reviewed.RouteAliases) != 0 {
		t.Fatalf("approval withdrawn but node still holds %v", reviewed.RouteAliases)
	}
	stored, err := c.Nodes.Get(ctx, again.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.RouteAliases) != 0 {
		t.Fatalf("release not persisted: stored aliases %v", stored.RouteAliases)
	}
	// The block is genuinely back: the next request gets it rather than a new one.
	reused, err := pool.Allocate(ctx, MeshnetID(1), lan)
	if err != nil {
		t.Fatal(err)
	}
	if reused != alias {
		t.Errorf("released block not reusable: got %s, want %s", reused, alias)
	}
}

// A subnet router usually advertises HOSTS, not the whole LAN. The first build
// gave each one a same-size block — a single address, taken from the pool base —
// so 192.168.1.222/32 became 100.96.0.0/32, printed directly under the sentence
// promising the last octet would not change. Reported from the console.
func TestHostRoutesKeepTheirLastOctetAndShareABlock(t *testing.T) {
	ctx := context.Background()
	n := &Node{
		ApprovedRoutes: prefixes(t, "192.168.1.222/32", "192.168.1.22/32"),
		AliasedRoutes:  prefixes(t, "192.168.1.222/32", "192.168.1.22/32"),
	}
	keep, _, err := reconcileAliases(ctx, NewMemAliasIPAM(), MeshnetID(1), n, math.MaxInt)
	if err != nil {
		t.Fatal(err)
	}
	if len(keep) != 2 {
		t.Fatalf("aliased %v, want both", keep)
	}

	byReal := map[string]netip.Prefix{}
	for _, ra := range keep {
		byReal[ra.Real.String()] = ra.Alias
		if ra.Alias.Bits() != 32 {
			t.Errorf("%s -> %s: alias must stay a /32", ra.Real, ra.Alias)
		}
		// The promise the console prints.
		if got, want := ra.Alias.Addr().As4()[3], ra.Real.Addr().As4()[3]; got != want {
			t.Errorf("%s -> %s: last octet became %d, want %d", ra.Real, ra.Alias, got, want)
		}
		if ra.Alias.Addr().As4()[3] == 0 {
			t.Errorf("%s -> %s: handed out a network address", ra.Real, ra.Alias)
		}
	}
	// Two hosts from one LAN belong together.
	a, b := byReal["192.168.1.222/32"], byReal["192.168.1.22/32"]
	if containingBlock(a) != containingBlock(b) {
		t.Errorf("hosts of one /24 got different blocks: %s and %s", a, b)
	}
}

// Hosts from DIFFERENT LANs must not share a block, or their last octets would
// collide inside it.
func TestHostRoutesFromDifferentLansGetDifferentBlocks(t *testing.T) {
	n := &Node{
		ApprovedRoutes: prefixes(t, "192.168.1.5/32", "10.9.9.5/32"),
		AliasedRoutes:  prefixes(t, "192.168.1.5/32", "10.9.9.5/32"),
	}
	keep, _, err := reconcileAliases(context.Background(), NewMemAliasIPAM(), MeshnetID(1), n, math.MaxInt)
	if err != nil || len(keep) != 2 {
		t.Fatalf("keep=%v err=%v", keep, err)
	}
	if containingBlock(keep[0].Alias) == containingBlock(keep[1].Alias) {
		t.Fatalf("two LANs share one block: %s and %s", keep[0].Alias, keep[1].Alias)
	}
}

// The block is what was allocated, so the block is what goes back — but only
// once no sibling still lives in it. Releasing the /32 would leak the other 255
// addresses; releasing the block early would hand a live address to someone else.
func TestHostRouteBlockIsReleasedOnlyWhenEmpty(t *testing.T) {
	ctx := context.Background()
	pool := NewMemAliasIPAM()
	both := prefixes(t, "192.168.1.222/32", "192.168.1.22/32")
	n := &Node{ApprovedRoutes: both, AliasedRoutes: both}

	keep, _, err := reconcileAliases(ctx, pool, MeshnetID(1), n, math.MaxInt)
	if err != nil {
		t.Fatal(err)
	}
	n.RouteAliases = keep
	block := containingBlock(keep[0].Alias)

	// Drop one of the two: the block is still in use.
	one := prefixes(t, "192.168.1.222/32")
	n.ApprovedRoutes, n.AliasedRoutes = one, one
	keep, release, err := reconcileAliases(ctx, pool, MeshnetID(1), n, math.MaxInt)
	if err != nil {
		t.Fatal(err)
	}
	if len(release) != 0 {
		t.Fatalf("released %v while a sibling still uses the block", release)
	}
	n.RouteAliases = keep

	// Drop the last one: now the whole block goes back.
	n.ApprovedRoutes, n.AliasedRoutes = nil, nil
	keep, release, err = reconcileAliases(ctx, pool, MeshnetID(1), n, math.MaxInt)
	if err != nil {
		t.Fatal(err)
	}
	if len(keep) != 0 {
		t.Fatalf("kept %v after everything was withdrawn", keep)
	}
	if len(release) != 1 || release[0] != block {
		t.Fatalf("released %v, want the block %s", release, block)
	}
}

// A whole-subnet advertisement is unchanged: a same-size block already preserves
// every host bit, so it must not be pushed through the grouping path.
func TestWholeSubnetsStillGetASameSizeBlock(t *testing.T) {
	n := &Node{
		ApprovedRoutes: prefixes(t, "192.168.1.0/24", "10.9.0.0/16"),
		AliasedRoutes:  prefixes(t, "192.168.1.0/24", "10.9.0.0/16"),
	}
	keep, _, err := reconcileAliases(context.Background(), NewMemAliasIPAM(), MeshnetID(1), n, math.MaxInt)
	if err != nil {
		t.Fatal(err)
	}
	for _, ra := range keep {
		if ra.Alias.Bits() != ra.Real.Bits() {
			t.Errorf("%s -> %s: size changed", ra.Real, ra.Alias)
		}
	}
}

// A sub-range keeps its own length and its offset inside the /24.
func TestSubRangeKeepsItsLengthAndOffset(t *testing.T) {
	n := &Node{
		ApprovedRoutes: prefixes(t, "192.168.1.128/25"),
		AliasedRoutes:  prefixes(t, "192.168.1.128/25"),
	}
	keep, _, err := reconcileAliases(context.Background(), NewMemAliasIPAM(), MeshnetID(1), n, math.MaxInt)
	if err != nil || len(keep) != 1 {
		t.Fatalf("keep=%v err=%v", keep, err)
	}
	a := keep[0].Alias
	if a.Bits() != 25 {
		t.Errorf("alias %s: want a /25", a)
	}
	if a.Addr().As4()[3] != 128 {
		t.Errorf("alias %s: offset within the block changed", a)
	}
	if a != a.Masked() {
		t.Errorf("alias %s is not aligned", a)
	}
}

// The alias pool is one platform-wide range, and nothing else bounds it: a node
// self-asserts its routes and an unreviewed node's claims are auto-approved. So
// without a cap one org drains it — and the orgs that then cannot alias a
// colliding subnet are OTHER orgs, while the one that drained it is unaffected.
func TestAliasBudgetStopsNewAllocationsButKeepsWhatWorks(t *testing.T) {
	ctx := context.Background()
	pool := NewMemAliasIPAM()

	// One /24 of budget: one whole-subnet route fits, the second does not.
	two := prefixes(t, "192.168.1.0/24", "10.9.9.0/24")
	n := &Node{ApprovedRoutes: two, AliasedRoutes: two}

	keep, _, err := reconcileAliases(ctx, pool, MeshnetID(1), n, DefaultAliasAddrBudget)
	if !errors.Is(err, ErrAliasBudgetExhausted) {
		t.Fatalf("err = %v, want ErrAliasBudgetExhausted", err)
	}
	if len(keep) != 1 {
		t.Fatalf("aliased %v, want exactly the one that fits", keep)
	}
	n.RouteAliases = keep

	// Re-registering must not lose the one it has, even though it is now at the
	// cap: lowering or reaching a budget cannot break a route that works.
	again, release, err := reconcileAliases(ctx, pool, MeshnetID(1), n, DefaultAliasAddrBudget)
	if len(again) != 1 || again[0] != keep[0] {
		t.Fatalf("kept %v, want the existing %v", again, keep)
	}
	if len(release) != 0 {
		t.Fatalf("released %v while at budget", release)
	}
	if !errors.Is(err, ErrAliasBudgetExhausted) {
		t.Errorf("err = %v, want the refusal to still be reported", err)
	}
}

// Host routes out of one /24 share a block, so the second and third are free.
// Charging each /32 a whole block would price an ordinary subnet router out of
// the default budget for space it never took.
func TestAliasBudgetChargesBlocksNotRoutes(t *testing.T) {
	hosts := prefixes(t, "192.168.1.22/32", "192.168.1.222/32", "192.168.1.9/32")
	n := &Node{ApprovedRoutes: hosts, AliasedRoutes: hosts}

	keep, _, err := reconcileAliases(context.Background(), NewMemAliasIPAM(), MeshnetID(1), n, DefaultAliasAddrBudget)
	if err != nil {
		t.Fatalf("three hosts of one /24 must fit in one /24 of budget: %v", err)
	}
	if len(keep) != 3 {
		t.Fatalf("aliased %v, want all three", keep)
	}
	if got := AliasSpend(keep); got != 256 {
		t.Errorf("spend = %d, want 256 (one shared block)", got)
	}
}

// A big LAN is priced like one: a /16 is 256 blocks' worth, so it does not fit
// the default budget and publishes under its real CIDR instead.
func TestAliasBudgetPricesLargeSubnets(t *testing.T) {
	big := prefixes(t, "10.9.0.0/16")
	n := &Node{ApprovedRoutes: big, AliasedRoutes: big}

	keep, _, err := reconcileAliases(context.Background(), NewMemAliasIPAM(), MeshnetID(1), n, DefaultAliasAddrBudget)
	if !errors.Is(err, ErrAliasBudgetExhausted) {
		t.Fatalf("err = %v, want the /16 to be refused at the default budget", err)
	}
	if len(keep) != 0 {
		t.Fatalf("aliased %v, want none", keep)
	}
	// Raised by an admin, it fits.
	keep, _, err = reconcileAliases(context.Background(), NewMemAliasIPAM(), MeshnetID(1), n, 1<<16)
	if err != nil || len(keep) != 1 {
		t.Fatalf("with a raised budget: keep=%v err=%v", keep, err)
	}
}

func TestAliasSpend(t *testing.T) {
	sub := RouteAlias{Real: pfx(t, "192.168.1.0/24"), Alias: pfx(t, "100.96.0.0/24")}
	h1 := RouteAlias{Real: pfx(t, "10.0.0.5/32"), Alias: pfx(t, "100.97.0.5/32")}
	h2 := RouteAlias{Real: pfx(t, "10.0.0.6/32"), Alias: pfx(t, "100.97.0.6/32")}
	if got := AliasSpend([]RouteAlias{sub}); got != 256 {
		t.Errorf("a /24 subnet = %d, want 256", got)
	}
	if got := AliasSpend([]RouteAlias{h1, h2}); got != 256 {
		t.Errorf("two hosts of one block = %d, want 256 (charged once)", got)
	}
	if got := AliasSpend([]RouteAlias{sub, h1, h2}); got != 512 {
		t.Errorf("a subnet plus a host block = %d, want 512", got)
	}
	if got := AliasSpend(nil); got != 0 {
		t.Errorf("nothing = %d, want 0", got)
	}
}

func TestRealRouteAccessKeepsAliasesAndAdminDecision(t *testing.T) {
	ctx := context.Background()
	c := newTestCoord()
	c.AliasIPAM = NewMemAliasIPAM()
	lan := pfx(t, "192.168.1.0/24")
	in := RegisterInput{Meshnet: 1, Name: "router", NodeKey: key(1), AdvertisedRoutes: []netip.Prefix{lan}, AliasedRoutes: []netip.Prefix{lan}}
	n, err := c.Register(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	n, err = c.ApproveRoutes(ctx, 1, n.ID, []netip.Prefix{lan})
	if err != nil {
		t.Fatal(err)
	}
	alias := n.RouteAliases[0].Alias
	if routes := PublishedRoutes(n); len(routes) != 1 || routes[0] != alias {
		t.Fatalf("default routes %v", routes)
	}
	n, err = c.ApproveRoutes(ctx, 1, n.ID, []netip.Prefix{lan}, []netip.Prefix{lan})
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "consumer", NodeKey: key(2)})
	if err != nil {
		t.Fatal(err)
	}
	nm, err := c.NetMapFor(ctx, consumer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(nm.Peers) != 1 {
		t.Fatalf("peers %v", nm.Peers)
	}
	pub := PublishedRoutes(&nm.Peers[0])
	if len(pub) != 2 || !containsPrefix(pub, lan) || !containsPrefix(pub, alias) {
		t.Fatalf("dual routes %v", pub)
	}
	// Both source selectors are needed after conntrack ages out.
	cidrs := sourceCIDRs([]string{n.Name}, []*Node{n}, nil, nil)
	found := map[string]bool{}
	for _, r := range cidrs {
		found[r] = true
	}
	if !found[lan.String()] || !found[alias.String()] {
		t.Fatalf("ACL selectors %v", cidrs)
	}
	n, err = c.Register(ctx, in)
	if err != nil || !containsPrefix(n.RealRoutes, lan) {
		t.Fatalf("re-register lost decision: %+v %v", n, err)
	}
	// Older callers omit the new field, preserving the administrator's choice.
	n, err = c.ApproveRoutes(ctx, 1, n.ID, []netip.Prefix{lan})
	if err != nil || !containsPrefix(n.RealRoutes, lan) {
		t.Fatalf("old caller reset selection: %+v %v", n, err)
	}
	n, err = c.ApproveRoutes(ctx, 1, n.ID, []netip.Prefix{lan}, []netip.Prefix{})
	if err != nil || len(n.RealRoutes) != 0 || len(n.RouteAliases) != 1 || n.RouteAliases[0].Alias != alias {
		t.Fatalf("disable: %+v %v", n, err)
	}
	n, err = c.ApproveRoutes(ctx, 1, n.ID, []netip.Prefix{lan}, []netip.Prefix{lan})
	if err != nil {
		t.Fatal(err)
	}
	n, err = c.ApproveRoutes(ctx, 1, n.ID, nil)
	if err != nil || len(n.RealRoutes) != 0 || len(PublishedRoutes(n)) != 0 {
		t.Fatalf("revocation: %+v %v", n, err)
	}
	if _, err = c.ApproveRoutes(ctx, 2, n.ID, []netip.Prefix{lan}, []netip.Prefix{lan}); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("cross org: %v", err)
	}
	if _, err = c.ApproveRoutes(ctx, 1, n.ID, nil, []netip.Prefix{lan}); !errors.Is(err, ErrRouteNotAdvertised) {
		t.Fatalf("unapproved real route: %v", err)
	}
}

func TestRealRoutesRejectAmbiguityAndRecheckNetmaps(t *testing.T) {
	ctx := context.Background()
	c := newTestCoord()
	c.AliasIPAM = NewMemAliasIPAM()
	c.Settings = NewMemSettingsStore()
	if err := c.Settings.SetSettings(ctx, 1, MeshnetSettings{AliasAddrBudget: 512}); err != nil {
		t.Fatal(err)
	}
	lan := pfx(t, "192.168.1.0/24")
	var nodes []*Node
	for i := byte(1); i <= 2; i++ {
		n, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: string('a' + i), NodeKey: key(i), AdvertisedRoutes: []netip.Prefix{lan}, AliasedRoutes: []netip.Prefix{lan}})
		if err != nil {
			t.Fatal(err)
		}
		n, err = c.ApproveRoutes(ctx, 1, n.ID, []netip.Prefix{lan})
		if err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, n)
	}
	if _, err := c.ApproveRoutes(ctx, 1, nodes[0].ID, []netip.Prefix{lan}, []netip.Prefix{lan}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApproveRoutes(ctx, 1, nodes[1].ID, []netip.Prefix{lan}, []netip.Prefix{lan}); !errors.Is(err, ErrRouteNotAdvertised) {
		t.Fatalf("ambiguous address accepted: %v", err)
	}
	// Simulate another legacy router later losing alias support. The configured
	// opt-in must stop advertising its real range, while keeping its alias.
	other := *nodes[1]
	other.RouteAliases = nil
	if _, err := c.Nodes.Upsert(ctx, &other); err != nil {
		t.Fatal(err)
	}
	consumer, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "consumer", NodeKey: key(3)})
	if err != nil {
		t.Fatal(err)
	}
	nm, err := c.NetMapFor(ctx, consumer.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range nm.Peers {
		if peer.ID == nodes[0].ID {
			pub := PublishedRoutes(&peer)
			if containsPrefix(pub, lan) || !containsPrefix(pub, nodes[0].RouteAliases[0].Alias) {
				t.Fatalf("unsafe map routes %v", pub)
			}
		}
	}
	// A conflict must not prevent retaining or later reducing an existing grant.
	if _, err := c.ApproveRoutes(ctx, 1, nodes[0].ID, []netip.Prefix{lan}, []netip.Prefix{lan}); err != nil {
		t.Fatal(err)
	}
	stored, err := c.Nodes.Get(ctx, nodes[0].ID)
	if err != nil || !containsPrefix(stored.RealRoutes, lan) {
		t.Fatalf("map computation modified stored decision: %+v %v", stored, err)
	}
}

func TestRealTargetsBehindRouterNeedNoClient(t *testing.T) {
	ctx := context.Background()
	c := newTestCoord()
	c.AliasIPAM = NewMemAliasIPAM()
	subnet := pfx(t, "192.168.1.0/24")
	target := pfx(t, "192.168.1.50/32")
	other := pfx(t, "192.168.1.80/32")
	router, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "site-router", NodeKey: key(1), AdvertisedRoutes: []netip.Prefix{subnet}, AliasedRoutes: []netip.Prefix{subnet}})
	if err != nil {
		t.Fatal(err)
	}
	router, err = c.ApproveRoutes(ctx, 1, router.ID, []netip.Prefix{subnet}, []netip.Prefix{target})
	if err != nil {
		t.Fatal(err)
	}
	alias := router.RouteAliases[0].Alias
	consumer, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "visitor", NodeKey: key(2)})
	if err != nil {
		t.Fatal(err)
	}
	// Only the router and visitor are enrolled. The NAS at .50 has no mesh
	// identity, key, process, or device record of its own.
	nodes, err := c.Nodes.ListMeshnet(ctx, 1)
	if err != nil || len(nodes) != 2 {
		t.Fatalf("unexpected enrolled devices: %v %v", nodes, err)
	}
	nm, err := c.NetMapFor(ctx, consumer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(nm.Peers) != 1 || nm.Peers[0].ID != router.ID {
		t.Fatalf("target must route through publisher: %+v", nm.Peers)
	}
	routes := PublishedRoutes(&nm.Peers[0])
	if len(routes) != 2 || !containsPrefix(routes, alias) || !containsPrefix(routes, target) || containsPrefix(routes, subnet) || containsPrefix(routes, other) {
		t.Fatalf("target selection leaked: %v", routes)
	}
	cidrs := sourceCIDRs([]string{router.Name}, []*Node{router}, nil, nil)
	found := map[string]bool{}
	for _, cidr := range cidrs {
		found[cidr] = true
	}
	if !found[target.String()] || !found[alias.String()] || found[subnet.String()] || found[other.String()] {
		t.Fatalf("return-packet ACL %v", cidrs)
	}
	// Re-saving approvals from an older caller must preserve a selected host
	// inside the /24, not require it to have been advertised separately.
	router, err = c.ApproveRoutes(ctx, 1, router.ID, []netip.Prefix{subnet})
	if err != nil || !containsPrefix(router.RealRoutes, target) {
		t.Fatalf("lost host selection: %+v %v", router, err)
	}
	for _, invalid := range []netip.Prefix{pfx(t, "192.168.2.50/32"), pfx(t, "192.168.0.0/16"), pfx(t, "0.0.0.0/0"), pfx(t, "fd00::50/128")} {
		if _, err := c.ApproveRoutes(ctx, 1, router.ID, []netip.Prefix{subnet}, []netip.Prefix{invalid}); !errors.Is(err, ErrRouteNotAdvertised) {
			t.Fatalf("accepted target outside approved subnet %s: %v", invalid, err)
		}
	}
	router, err = c.ApproveRoutes(ctx, 1, router.ID, nil)
	if err != nil || len(router.RealRoutes) != 0 || len(PublishedRoutes(router)) != 0 {
		t.Fatalf("revocation did not remove child hosts: %+v %v", router, err)
	}
	if targets := SelectedRealRoutes([]netip.Prefix{target}, prefixes(t, "0.0.0.0/0")); len(targets) != 0 {
		t.Fatalf("exit route authorized targets: %v", targets)
	}
}

func TestSeparateSitesMayExposeDifferentHostsFromSameSubnet(t *testing.T) {
	ctx := context.Background()
	c := newTestCoord()
	c.AliasIPAM = NewMemAliasIPAM()
	c.Settings = NewMemSettingsStore()
	if err := c.Settings.SetSettings(ctx, 1, MeshnetSettings{AliasAddrBudget: 512}); err != nil {
		t.Fatal(err)
	}
	subnet := pfx(t, "192.168.1.0/24")
	var routers []*Node
	for i, target := range prefixes(t, "192.168.1.50/32", "192.168.1.80/32") {
		n, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: string('a' + rune(i)), NodeKey: key(byte(i + 1)), AdvertisedRoutes: []netip.Prefix{subnet}, AliasedRoutes: []netip.Prefix{subnet}})
		if err != nil {
			t.Fatal(err)
		}
		n, err = c.ApproveRoutes(ctx, 1, n.ID, []netip.Prefix{subnet}, []netip.Prefix{target})
		if err != nil {
			t.Fatalf("different targets should coexist: %v", err)
		}
		routers = append(routers, n)
	}
	if _, err := c.ApproveRoutes(ctx, 1, routers[1].ID, []netip.Prefix{subnet}, prefixes(t, "192.168.1.50/32")); !errors.Is(err, ErrRouteNotAdvertised) {
		t.Fatalf("same target claimed by two routers: %v", err)
	}
	for _, router := range safeRealRoutes(routers) {
		if len(router.RealRoutes) != 1 || len(PublishedRoutes(router)) != 2 {
			t.Fatalf("nonconflicting target suppressed: %+v", router)
		}
	}
}
