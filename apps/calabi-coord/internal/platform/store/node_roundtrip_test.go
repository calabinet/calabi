package store

import (
	"context"
	"net/netip"
	"reflect"
	"testing"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// Every field of core.Node, sorted by how the database store treats it. The
// mapping in store.go is written out by hand, field by field — the shape that
// has dropped a field silently more than once (device_fingerprint could never
// be set on update; see the note in Upsert). This test enumerates the struct by
// reflection and fails on a field nobody sorted, so adding one to core.Node
// forces the question "does the store keep it?".
var nodeFieldHandling = map[string]string{
	// Written by Upsert on insert AND on update: what the node reports, or
	// what core.Register decides on its behalf.
	"Meshnet": "both", "Name": "both", "HostName": "both", "NamePinned": "both",
	"NodeKey": "both", "DiscoKey": "both", "Overlay": "both", "Endpoints": "both",
	"DERPHome": "both", "AdvertisedRoutes": "both", "ApprovedRoutes": "both",
	"RoutesReviewed": "both", "AliasedRoutes": "both", "RouteAliases": "both",
	"OwnerUserID": "both", "Tags": "both", "DeviceFingerprint": "both", "OS": "both",
	"BlockIncoming": "both", "EnrolledBy": "both", "SignedOut": "both",
	// Admin decisions: set on insert, never by a node's own re-enrolment
	// (each has its own setter).
	"Approved": "insert", "TagsPinned": "insert",
	// Only through its own setter (SetDisabled).
	"Disabled": "setter",
	// Not stored on the row: assigned by the database, or computed elsewhere.
	"ID": "none", "CreatedAt": "none", "LastSeen": "none", "Services": "none",
}

// nodeWith fills every stored field with a value distinct per variant.
func nodeWith(v byte) *core.Node {
	b := v%2 == 1
	return &core.Node{
		Meshnet:           1,
		Name:              "name-" + string('a'+v),
		HostName:          "host-" + string('a'+v),
		NamePinned:        b,
		NodeKey:           key(1),
		DiscoKey:          meshproto.DiscoKey{v, 9},
		Overlay:           netip.AddrFrom4([4]byte{100, 64, 0, v}),
		Endpoints:         []netip.AddrPort{netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, v}), 41641)},
		DERPHome:          "region-" + string('a'+v),
		AdvertisedRoutes:  []netip.Prefix{netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, v, 0}), 24)},
		ApprovedRoutes:    []netip.Prefix{netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, v, 0}), 24)},
		RoutesReviewed:    b,
		AliasedRoutes:     []netip.Prefix{netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, v, 0}), 24)},
		RouteAliases:      []core.RouteAlias{{Real: netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, v, 0}), 24), Alias: netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 96, v, 0}), 24)}},
		OwnerUserID:       int64(10 + v),
		Tags:              []string{"tag:t" + string('a'+v)},
		DeviceFingerprint: "fp-" + string('a'+v),
		OS:                "os-" + string('a'+v),
		BlockIncoming:     &b,
		EnrolledBy:        "user:" + string('1'+v),
		SignedOut:         b,
		Approved:          b,
		TagsPinned:        b,
	}
}

func TestNodeRoundTripEveryField(t *testing.T) {
	typ := reflect.TypeOf(core.Node{})
	for i := 0; i < typ.NumField(); i++ {
		if _, ok := nodeFieldHandling[typ.Field(i).Name]; !ok {
			t.Errorf("core.Node.%s is not in nodeFieldHandling: decide whether the database store keeps it, and write it through Upsert/toNode", typ.Field(i).Name)
		}
	}
	for name := range nodeFieldHandling {
		if _, ok := typ.FieldByName(name); !ok {
			t.Errorf("nodeFieldHandling lists %s, which core.Node no longer has", name)
		}
	}

	s := newTestStore(t)
	ctx := context.Background()
	first, second := nodeWith(1), nodeWith(2)

	saved, err := s.Upsert(ctx, first)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	got, err := s.Get(ctx, saved.ID)
	if err != nil {
		t.Fatal(err)
	}
	compare := func(stage string, got, want *core.Node, stored func(string) bool) {
		t.Helper()
		gv, wv := reflect.ValueOf(got).Elem(), reflect.ValueOf(want).Elem()
		for name, how := range nodeFieldHandling {
			if !stored(how) {
				continue
			}
			if g, w := gv.FieldByName(name).Interface(), wv.FieldByName(name).Interface(); !reflect.DeepEqual(g, w) {
				t.Errorf("%s: %s = %v, want %v", stage, name, g, w)
			}
		}
	}
	compare("after insert", got, first, func(how string) bool { return how == "both" || how == "insert" })

	second.ID = saved.ID
	if _, err := s.Upsert(ctx, second); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, err = s.Get(ctx, saved.ID)
	if err != nil {
		t.Fatal(err)
	}
	compare("after update", got, second, func(how string) bool { return how == "both" })
	// And the admin's decisions survived the node's update.
	compare("admin fields after update", got, first, func(how string) bool { return how == "insert" })

	if err := s.SetSignedOut(ctx, saved.ID, false); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Get(ctx, saved.ID); got.SignedOut {
		t.Error("SetSignedOut(false) did not persist")
	}
}
