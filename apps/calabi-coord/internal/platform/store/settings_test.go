package store

import (
	"context"
	"reflect"
	"testing"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
)

// Every field of core.MeshnetSettings must survive the database.
//
// Enumerated by reflection, not listed by hand, because a hand-written list is
// exactly how conn_records_disabled was lost: the field was added to the struct
// (2026-09-13), every core test passed against the in-memory store that keeps
// the whole struct, and the database store simply never had a column for it. An
// org that turned its connection records off kept being recorded. A field added
// from now on fails here until the store keeps it.
func TestSettingsRoundTripEveryField(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	var in core.MeshnetSettings
	v := reflect.ValueOf(&in).Elem()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		switch f.Kind() {
		case reflect.Bool:
			f.SetBool(true)
		case reflect.Int, reflect.Int32, reflect.Int64:
			f.SetInt(int64(1000 + i))
		default:
			t.Fatalf("MeshnetSettings.%s has kind %s: teach this test a non-zero value for it", v.Type().Field(i).Name, f.Kind())
		}
	}

	// Twice: the first write creates the row, the second updates it, and the two
	// are separate code paths.
	for _, pass := range []string{"create", "update"} {
		if err := s.SetSettings(ctx, 7, in); err != nil {
			t.Fatalf("%s: SetSettings: %v", pass, err)
		}
		got, err := s.GetSettings(ctx, 7)
		if err != nil {
			t.Fatalf("%s: GetSettings: %v", pass, err)
		}
		gv := reflect.ValueOf(got)
		for i := 0; i < v.NumField(); i++ {
			if !reflect.DeepEqual(gv.Field(i).Interface(), v.Field(i).Interface()) {
				t.Errorf("%s: MeshnetSettings.%s = %v after a round trip, want %v (the database store does not keep it)",
					pass, v.Type().Field(i).Name, gv.Field(i).Interface(), v.Field(i).Interface())
			}
		}
		// Flip everything back for the update pass.
		for i := 0; i < v.NumField(); i++ {
			if f := v.Field(i); f.Kind() == reflect.Bool {
				f.SetBool(!f.Bool())
			} else {
				f.SetInt(f.Int() + 1)
			}
		}
	}
}
