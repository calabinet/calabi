// connrecord_retention_test.go — the retention an operator sets from the admin
// console, and the bounds that are the RULE rather than a courtesy.
//
// The console limits its input box too, but that only constrains whoever is
// typing. Anything reaching the admin surface with curl meets this.
//
// RUN: go test./apps/calabi-coord/internal/core/ -run TestConnRecordRetention -v
package core

import (
	"context"
	"testing"
)

// memSettings is the smallest PlatformSettingStore that works.
type memSettings struct {
	m    map[string]string
	fail error
}

func newMemSettings() *memSettings { return &memSettings{m: map[string]string{}} }

func (s *memSettings) GetSetting(_ context.Context, k string) (string, bool, error) {
	if s.fail != nil {
		return "", false, s.fail
	}
	v, ok := s.m[k]
	return v, ok, nil
}

func (s *memSettings) SetSetting(_ context.Context, k, v string) error {
	if s.fail != nil {
		return s.fail
	}
	s.m[k] = v
	return nil
}

func TestConnRecordRetentionClampsOnWrite(t *testing.T) {
	c := &Coordinator{PlatformSettings: newMemSettings()}
	ctx := context.Background()

	for _, tc := range []struct{ in, want int }{
		{30, 30},
		{MaxConnRecordRetentionDays, MaxConnRecordRetentionDays},
		// Over the ceiling: stored at the ceiling, not refused — and the caller is
		// told what was stored so the console can show the real number instead of
		// echoing the one that was typed.
		{9999, MaxConnRecordRetentionDays},
		// Zero is not "off": there is a separate switch for that, and letting 0
		// mean off here would give two ways to say one thing.
		{0, MinConnRecordRetentionDays},
		{-5, MinConnRecordRetentionDays},
	} {
		got, err := c.SetConnRecordRetentionDays(ctx, tc.in)
		if err != nil {
			t.Fatalf("set %d: %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("set %d stored %d, want %d", tc.in, got, tc.want)
		}
		if back := c.ConnRecordRetentionDays(ctx); back != tc.want {
			t.Errorf("after set %d, read back %d, want %d", tc.in, back, tc.want)
		}
	}
}

// The stored value WINS over the deployment default, which is the whole point of
// putting it in the console: changing it must not need a redeploy.
func TestConnRecordRetentionStoredBeatsDefault(t *testing.T) {
	c := &Coordinator{PlatformSettings: newMemSettings(), ConnRecordRetentionDefaultDays: 30}
	ctx := context.Background()

	if got := c.ConnRecordRetentionDays(ctx); got != 30 {
		t.Fatalf("with nothing stored, got %d, want the deployment default 30", got)
	}
	if _, err := c.SetConnRecordRetentionDays(ctx, 7); err != nil {
		t.Fatalf("set: %v", err)
	}
	if got := c.ConnRecordRetentionDays(ctx); got != 7 {
		t.Fatalf("got %d, want the stored 7", got)
	}
}

// Every way of not knowing has to fall back to the default, never to "keep
// forever". The failure mode of a retention setting must be keeping LESS than
// intended: too little is a gap somebody notices, too much is a liability
// nobody does.
func TestConnRecordRetentionFailsShortNotLong(t *testing.T) {
	ctx := context.Background()

	// No store at all (a deployment with no DB).
	c := &Coordinator{ConnRecordRetentionDefaultDays: 45}
	if got := c.ConnRecordRetentionDays(ctx); got != 45 {
		t.Errorf("no store: got %d, want 45", got)
	}

	// Store that errors.
	broken := newMemSettings()
	broken.fail = context.DeadlineExceeded
	c = &Coordinator{PlatformSettings: broken, ConnRecordRetentionDefaultDays: 45}
	if got := c.ConnRecordRetentionDays(ctx); got != 45 {
		t.Errorf("broken store: got %d, want 45", got)
	}

	// Garbage in the column.
	junk := newMemSettings()
	junk.m[SettingConnRecordRetentionDays] = "forever"
	c = &Coordinator{PlatformSettings: junk, ConnRecordRetentionDefaultDays: 45}
	if got := c.ConnRecordRetentionDays(ctx); got != 45 {
		t.Errorf("unparseable value: got %d, want 45", got)
	}

	// A value someone wrote straight into the DB, past the ceiling.
	over := newMemSettings()
	over.m[SettingConnRecordRetentionDays] = "100000"
	c = &Coordinator{PlatformSettings: over}
	if got := c.ConnRecordRetentionDays(ctx); got != MaxConnRecordRetentionDays {
		t.Errorf("out-of-range stored value: got %d, want the ceiling %d", got, MaxConnRecordRetentionDays)
	}

	// No default configured at all.
	c = &Coordinator{PlatformSettings: newMemSettings()}
	if got := c.ConnRecordRetentionDays(ctx); got != DefaultConnRecordRetentionDays {
		t.Errorf("no default: got %d, want %d", got, DefaultConnRecordRetentionDays)
	}
}
