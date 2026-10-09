package mesh

import (
	"net/netip"
	"reflect"
	"testing"

	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
)

func prefixes(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// The self entry as a coordinator really sends it: overlay /32 first, then what
// it publishes for this node — the ALIAS where one was granted, the real CIDR
// otherwise, and the default route for an approved exit device.
func TestSelfPublishedRoutesNamesRoutesAsAdvertised(t *testing.T) {
	nm := NetMap{
		Self: Peer{
			Overlay:    netip.MustParseAddr("100.64.0.7"),
			AllowedIPs: prefixes("100.64.0.7/32", "100.96.5.0/24", "10.20.0.0/24", "0.0.0.0/0"),
		},
		SubnetAliases: []SubnetAlias{
			{Alias: netip.MustParsePrefix("100.96.5.0/24"), Real: netip.MustParsePrefix("192.168.1.0/24")},
		},
	}
	got := selfPublishedRoutes(nm)
	want := prefixes("192.168.1.0/24", "10.20.0.0/24", "0.0.0.0/0")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("published = %v, want %v", got, want)
	}
}

// The case the whole thing is for: the node advertises a route, nobody has
// approved it, and the coordinator's self entry carries the overlay address and
// nothing else. That must read as "nothing published", not as an unknown.
func TestSelfPublishedRoutesEmptyWhileAwaitingApproval(t *testing.T) {
	nm := NetMap{Self: Peer{
		Overlay:    netip.MustParseAddr("100.64.0.7"),
		AllowedIPs: prefixes("100.64.0.7/32"),
	}}
	if got := selfPublishedRoutes(nm); len(got) != 0 {
		t.Fatalf("published = %v, want none", got)
	}
	waiting := unpublishedRoutes(prefixes("192.168.1.0/24", "0.0.0.0/0"), selfPublishedRoutes(nm))
	if want := prefixes("192.168.1.0/24", "0.0.0.0/0"); !reflect.DeepEqual(waiting, want) {
		t.Fatalf("waiting = %v, want %v", waiting, want)
	}
}

// A host route is aliased to a host address, so the mapping has to hold at /32
// too — and a published /32 that is NOT the node's overlay must not be mistaken
// for it and dropped.
func TestSelfPublishedRoutesKeepsHostRoutes(t *testing.T) {
	nm := NetMap{
		Self: Peer{
			Overlay:    netip.MustParseAddr("100.64.0.7"),
			AllowedIPs: prefixes("100.64.0.7/32", "100.96.5.22/32", "10.9.1.4/32"),
		},
		SubnetAliases: []SubnetAlias{
			{Alias: netip.MustParsePrefix("100.96.5.22/32"), Real: netip.MustParsePrefix("192.168.1.22/32")},
		},
	}
	got := selfPublishedRoutes(nm)
	if want := prefixes("192.168.1.22/32", "10.9.1.4/32"); !reflect.DeepEqual(got, want) {
		t.Fatalf("published = %v, want %v", got, want)
	}
}

func TestUnpublishedRoutesIsAdvertisedMinusPublished(t *testing.T) {
	got := unpublishedRoutes(
		prefixes("192.168.1.0/24", "10.20.0.0/24", "0.0.0.0/0"),
		prefixes("10.20.0.0/24"),
	)
	if want := prefixes("192.168.1.0/24", "0.0.0.0/0"); !reflect.DeepEqual(got, want) {
		t.Fatalf("waiting = %v, want %v", got, want)
	}
	if got := unpublishedRoutes(prefixes("10.20.0.0/24"), prefixes("10.20.0.0/24")); len(got) != 0 {
		t.Fatalf("waiting = %v, want none", got)
	}
}

// End to end from the wire: the proto a coordinator sends, through FromNetMap
// and BuildWGConfig, to the field the datapath reports. The unit tests above
// would stay green if BuildWGConfig simply never filled it in.
func TestBuildWGConfigCarriesPublishedRoutesFromTheWire(t *testing.T) {
	pb := &meshpb.NetMap{
		Self: &meshpb.Peer{
			NodeId:      7,
			NodeKey:     keyB64(1),
			OverlayAddr: "100.64.0.7",
			AllowedIps:  []string{"100.64.0.7/32", "100.96.5.0/24"},
		},
		SubnetAliases: []*meshpb.SubnetAlias{{Alias: "100.96.5.0/24", Real: "192.168.1.0/24"}},
	}
	nm, err := FromNetMap(pb)
	if err != nil {
		t.Fatalf("FromNetMap: %v", err)
	}
	cfg := BuildWGConfig(nm)
	if want := prefixes("192.168.1.0/24"); !reflect.DeepEqual(cfg.PublishedRoutes, want) {
		t.Fatalf("cfg.PublishedRoutes = %v, want %v", cfg.PublishedRoutes, want)
	}
}

// The datapath is what the console reads. Before any netmap its empty list is
// "not told yet"; after a netmap with nothing published, the same empty list IS
// the answer — and only the second may be shown as a route waiting for approval.
func TestDatapathPublishedReportSeparatesUnknownFromNone(t *testing.T) {
	d := &WGDatapath{}
	if got, seen := d.publishedReport(); seen || len(got) != 0 {
		t.Fatalf("before any netmap: %v seen=%v, want none and unseen", got, seen)
	}
	d.setPublishedReport(WGConfig{})
	if got, seen := d.publishedReport(); !seen || len(got) != 0 {
		t.Fatalf("after an empty netmap: %v seen=%v, want none and seen", got, seen)
	}
	d.setPublishedReport(WGConfig{PublishedRoutes: prefixes("192.168.1.0/24")})
	got, seen := d.publishedReport()
	if want := prefixes("192.168.1.0/24"); !seen || !reflect.DeepEqual(got, want) {
		t.Fatalf("after approval: %v seen=%v, want %v and seen", got, seen, want)
	}
	// A withdrawn approval must clear it, not leave the last answer standing.
	d.setPublishedReport(WGConfig{})
	if got, _ := d.publishedReport(); len(got) != 0 {
		t.Fatalf("after the approval was withdrawn: %v, want none", got)
	}
}

func TestRoutesFingerprintIgnoresOrder(t *testing.T) {
	a := routesFingerprint(prefixes("192.168.1.0/24", "10.20.0.0/24"))
	b := routesFingerprint(prefixes("10.20.0.0/24", "192.168.1.0/24"))
	if a != b || a == "" {
		t.Fatalf("fingerprints %q and %q should match and be non-empty", a, b)
	}
	if routesFingerprint(nil) != "" {
		t.Fatal("an empty set must fingerprint as empty")
	}
}
