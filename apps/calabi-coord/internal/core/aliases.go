package core

import (
	"context"
	"errors"
	"net/netip"
	"sort"
)

// Reconciling a node's subnet aliases.
//
// An alias exists for a route only while BOTH halves hold: the node asked for it
// (AliasedRoutes — only the publisher knows its LAN collides with anything) and
// an admin approved the route (ApprovedRoutes — approving hands this node other
// people's traffic). Either half going away releases the block.
//
// Both halves are checked every time rather than on transitions, because the
// events that change them are a daemon re-registering with an edited config and
// an admin editing approvals, and neither tells us what it changed. Deriving the
// whole set from the current facts is the version that cannot drift.

// reconcileAliases returns the alias set a node should hold now, and the blocks
// that must go back to the pool. It never mutates the node.
//
// Existing allocations are KEPT: an alias is an address consumers have routes
// for, so re-drawing one on every re-registration would move a working subnet
// out from under them on a daemon restart. A route only changes alias by losing
// it first.
//
// pool may be nil (deployment does not offer aliasing) — then nothing is granted
// and everything currently held is released, which is the correct answer to
// "this coordinator no longer does aliases".
// aliasGroupBits is the granularity a HOST route is aliased at.
//
// A subnet router commonly advertises individual hosts (192.168.1.222/32), not
// the whole LAN. Allocating a same-size block for those — one address — throws
// away the property the whole scheme is sold on: alias.222 IS real.222, so
// somebody who knows the NAS is.222 finds it without consulting a table. The
// first build did exactly that and produced `192.168.1.222/32 -> 100.96.0.0/32`,
// which the console displayed directly under the sentence promising the last
// octet would not change.
//
// So a host route takes its alias from a /24 block reserved for the /24 it lives
// in, at the same offset. Two host routes from one LAN then share a block and
// visibly belong together.
//
// The /24 is an ASSUMPTION: a /32 does not carry its real netmask, and nothing
// in the advertisement tells us. It is safe for RFC1918 host routes (a /16 LAN
// with two same-last-octet hosts simply gets two blocks — correct, just less
// dense), and the alternative is making the publisher declare its netmask, which
// is a protocol and a config change for a case nobody has yet.
const aliasGroupBits = 24

// ErrAliasBudgetExhausted is returned when a route would take the meshnet past
// MeshnetSettings.AliasAddrBudget. The route is still published — under its real
// CIDR, which is where it was before aliases existed — so the cost is that
// consumers whose own LAN collides with it cannot reach it. Never fatal.
var ErrAliasBudgetExhausted = errors.New("core: meshnet is at its subnet-alias budget")

// aliasBlockOf is the pool space one alias occupies: the block that actually
// left the pool, and its size in addresses.
//
// Counting BLOCKS rather than routes is the honest measure. Host routes out of
// one /24 share a block, so the second and third cost nothing — charging each
// /32 a full block would price a normal subnet router out of the default budget
// for space it never took.
func aliasBlockOf(ra RouteAlias) (netip.Prefix, int) {
	if _, isHost := aliasGroupOf(ra.Real); isHost {
		b := containingBlock(ra.Alias)
		return b, int(blockSize(b.Bits()))
	}
	return ra.Alias, int(blockSize(ra.Alias.Bits()))
}

// AliasSpend is the pool space a set of aliases occupies, in addresses. Exported
// so the coordinator can total up a meshnet's other nodes.
func AliasSpend(as []RouteAlias) int {
	seen := map[netip.Prefix]bool{}
	total := 0
	for _, ra := range as {
		b, size := aliasBlockOf(ra)
		if seen[b] {
			continue
		}
		seen[b] = true
		total += size
	}
	return total
}

// reconcileAliases decides a node's alias set. budgetAddrs is how much pool
// space THIS node may occupy (the meshnet's budget less what its other nodes
// hold); aliases it already holds count against it but are never taken away for
// being over — lowering a budget must not break routes that work today.
func reconcileAliases(ctx context.Context, pool AliasIPAM, t MeshnetID, node *Node, budgetAddrs int) (keep []RouteAlias, release []netip.Prefix, err error) {
	held := make(map[netip.Prefix]RouteAlias, len(node.RouteAliases))
	for _, ra := range node.RouteAliases {
		held[ra.Real.Masked()] = RouteAlias{Real: ra.Real.Masked(), Alias: ra.Alias}
	}
	// Alias blocks already in use by this node's host routes, keyed by the real
	// /24 they serve. Seeded from what is held so a re-registration reuses the
	// block instead of drawing a second one for the same LAN.
	blocks := map[netip.Prefix]netip.Prefix{}
	for _, ra := range held {
		if g, ok := aliasGroupOf(ra.Real); ok {
			blocks[g] = containingBlock(ra.Alias)
		}
	}

	// Pool space this node is already committed to, counted per block so the
	// budget prices what actually left the pool.
	spent := map[netip.Prefix]int{}
	spendTotal := func() int {
		n := 0
		for _, size := range spent {
			n += size
		}
		return n
	}
	charge := func(ra RouteAlias) {
		b, size := aliasBlockOf(ra)
		spent[b] = size
	}

	for _, real := range wantedAliases(node) {
		if ra, ok := held[real]; ok {
			keep = append(keep, ra)
			charge(ra)
			delete(held, real)
			continue
		}
		if pool == nil {
			continue
		}
		// Would this route need a NEW block, and does the budget have room? A host
		// route joining a block this node already holds costs nothing.
		if cost, isNew := aliasCostOf(real, blocks); isNew && spendTotal()+cost > budgetAddrs {
			err = ErrAliasBudgetExhausted
			continue
		}
		alias, aerr := allocateAlias(ctx, pool, t, real, blocks)
		if aerr != nil {
			// A route that cannot be aliased is published under its real CIDR
			// rather than failing the whole registration: the node is on the mesh
			// either way, and taking it off because one subnet is too big to alias
			// would be a far worse trade. The caller logs it.
			err = aerr
			continue
		}
		ra := RouteAlias{Real: real, Alias: alias}
		keep = append(keep, ra)
		charge(ra)
	}

	release = releasable(keep, held)
	sort.Slice(keep, func(i, j int) bool { return keep[i].Real.String() < keep[j].Real.String() })
	sort.Slice(release, func(i, j int) bool { return release[i].String() < release[j].String() })
	return keep, release, err
}

// allocateAlias draws an alias for one route, reserving (or reusing) a /24 block
// when the route is a host route. blocks is updated in place.
func allocateAlias(ctx context.Context, pool AliasIPAM, t MeshnetID, real netip.Prefix, blocks map[netip.Prefix]netip.Prefix) (netip.Prefix, error) {
	group, isHost := aliasGroupOf(real)
	if !isHost {
		// A whole subnet: a same-size block already preserves every host bit.
		return pool.Allocate(ctx, t, real)
	}
	block, ok := blocks[group]
	if !ok {
		// Ask for a block the size of the GROUP, not of the route.
		b, err := pool.Allocate(ctx, t, group)
		if err != nil {
			return netip.Prefix{}, err
		}
		block, blocks[group] = b, b
	}
	// Same offset within the block as the real address has within its own /24.
	// A prefix aligned inside its /24 lands aligned inside the alias /24, so this
	// is a valid prefix for any length from /25 to /32.
	offset := u32(real.Addr()) - u32(group.Addr())
	return netip.PrefixFrom(addr4(u32(block.Addr())+offset), real.Bits()), nil
}

// aliasGroupOf returns the /24 a HOST route lives in. ok=false for a route that
// is a whole subnet (/24 or wider), which needs no grouping.
func aliasGroupOf(real netip.Prefix) (netip.Prefix, bool) {
	if !real.Addr().Is4() || real.Bits() <= aliasGroupBits {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(real.Addr(), aliasGroupBits).Masked(), true
}

// containingBlock is the /24 an alias was carved out of.
func containingBlock(alias netip.Prefix) netip.Prefix {
	return netip.PrefixFrom(alias.Addr(), aliasGroupBits).Masked()
}

// releasable is what goes back to the pool: every alias no longer wanted, EXCEPT
// that a host route's alias is one address out of a /24 block — the block is what
// was allocated and the block is what must be returned, and only once no kept
// route still lives in it. Returning the /32 instead would leak the other 255
// addresses forever; returning the block while a sibling still uses it would hand
// a live address to somebody else.
func releasable(keep []RouteAlias, dropped map[netip.Prefix]RouteAlias) []netip.Prefix {
	stillUsed := map[netip.Prefix]bool{}
	for _, ra := range keep {
		if _, isHost := aliasGroupOf(ra.Real); isHost {
			stillUsed[containingBlock(ra.Alias)] = true
		}
	}
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, ra := range dropped {
		free := ra.Alias
		if _, isHost := aliasGroupOf(ra.Real); isHost {
			block := containingBlock(ra.Alias)
			if stillUsed[block] {
				continue // a sibling host route still lives in it
			}
			free = block
		}
		if seen[free] {
			continue
		}
		seen[free] = true
		out = append(out, free)
	}
	return out
}

// wantedAliases is the set of routes that should carry an alias: requested by
// the node AND approved by an admin, de-duplicated and masked.
func wantedAliases(node *Node) []netip.Prefix {
	approved := make(map[netip.Prefix]bool, len(node.ApprovedRoutes))
	for _, r := range node.ApprovedRoutes {
		approved[r.Masked()] = true
	}
	seen := make(map[netip.Prefix]bool, len(node.AliasedRoutes))
	var out []netip.Prefix
	for _, r := range node.AliasedRoutes {
		m := r.Masked()
		if !approved[m] || seen[m] {
			continue
		}
		seen[m] = true
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// aliasFor returns the stand-in prefix published for real, if one was allocated.
func aliasFor(aliases []RouteAlias, real netip.Prefix) (netip.Prefix, bool) {
	m := real.Masked()
	for _, ra := range aliases {
		if ra.Real.Masked() == m {
			return ra.Alias, true
		}
	}
	return netip.Prefix{}, false
}

// PublishedRoutes is what a node's PEERS are told to route here: the alias where
// one exists, the real CIDR otherwise.
//
// Deliberately all-or-nothing per route rather than "the colliding consumers get
// the alias, the rest get the real CIDR". Telling them apart would mean every
// consumer reporting its local subnets to the coordinator — more moving parts,
// and a map of everyone's home networks held centrally, to save some consumers a
// change of address. The alias works for consumers that do not collide too.
func PublishedRoutes(node *Node) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(node.ApprovedRoutes))
	for _, r := range node.ApprovedRoutes {
		if alias, ok := aliasFor(node.RouteAliases, r); ok {
			out = append(out, alias)
			continue
		}
		out = append(out, r)
	}
	return out
}

// aliasCostOf is what a route would take from the pool, and whether it takes
// anything at all: a host route landing in a block this node already reserved
// is free.
func aliasCostOf(real netip.Prefix, blocks map[netip.Prefix]netip.Prefix) (cost int, isNew bool) {
	group, isHost := aliasGroupOf(real)
	if !isHost {
		return int(blockSize(real.Bits())), true
	}
	if _, held := blocks[group]; held {
		return 0, false
	}
	return int(blockSize(aliasGroupBits)), true
}

// unaliasedRoutes is what the node asked to alias, was approved for, and did not
// get: "wanted" minus "allocated". Derived rather than stored — the two inputs
// are already on the node, and a stored copy is one more thing that can drift
// from the allocation it describes.
func unaliasedRoutes(node *Node) []netip.Prefix {
	if len(node.AliasedRoutes) == 0 {
		return nil
	}
	got := make(map[netip.Prefix]bool, len(node.RouteAliases))
	for _, ra := range node.RouteAliases {
		got[ra.Real.Masked()] = true
	}
	var out []netip.Prefix
	for _, real := range wantedAliases(node) {
		if !got[real] {
			out = append(out, real)
		}
	}
	return out
}
