package store

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
)

// Every field of core.Relay survives the real database, on create and on
// update. The in-memory store keeps the whole struct, so its tests pass whether
// or not this adapter maps a field — which is how a field goes missing from the
// platform while every unit test stays green. Walked by reflection, so a field
// added to core.Relay later fails here until the adapter carries it.
func TestRelayRoundTripEveryField(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	in := core.Relay{Meshnet: 7, Label: "tokyo", HostName: "203.0.113.9", DERPPort: 3340, STUNPort: 3478, Enabled: true}
	fillRelay(t, &in)
	created, err := s.CreateRelay(ctx, in)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	checkRelay(t, s, *created, "after create")

	up := *created
	up.HostName, up.DERPPort, up.STUNPort = "198.51.100.4", 3341, 3479
	flipRelay(t, &up)
	if err := s.UpdateRelay(ctx, up); err != nil {
		t.Fatalf("update: %v", err)
	}
	checkRelay(t, s, up, "after update")
}

// fillRelay sets every bool field true, so a column the adapter never writes
// reads back as its zero value and shows.
func fillRelay(t *testing.T, r *core.Relay) {
	t.Helper()
	v := reflect.ValueOf(r).Elem()
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).Kind() == reflect.Bool {
			v.Field(i).SetBool(true)
		}
	}
}

// flipRelay inverts every bool field except Enabled — which the update path
// sets explicitly — so an update that skips a column shows too.
func flipRelay(t *testing.T, r *core.Relay) {
	t.Helper()
	v := reflect.ValueOf(r).Elem()
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).Kind() == reflect.Bool && v.Type().Field(i).Name != "Enabled" {
			v.Field(i).SetBool(!v.Field(i).Bool())
		}
	}
}

func checkRelay(t *testing.T, s *Store, want core.Relay, when string) {
	t.Helper()
	list, err := s.ListRelays(context.Background(), want.Meshnet)
	if err != nil || len(list) != 1 {
		t.Fatalf("%s: list = %+v, %v", when, list, err)
	}
	got := list[0]
	// CreatedAt is the database's; compare it loosely and drop it.
	if got.CreatedAt.IsZero() || time.Since(got.CreatedAt) > time.Minute {
		t.Errorf("%s: created_at = %v", when, got.CreatedAt)
	}
	got.CreatedAt, want.CreatedAt = time.Time{}, time.Time{}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s:\n got %+v\nwant %+v", when, got, want)
	}
}
