package core

import (
	"context"
	"fmt"
	"strconv"
)

// Platform-wide operational values an operator sets from the admin console, as
// opposed to MeshnetSettings, which belong to the org that owns the meshnet.
//
// The store is key/value; every key gets a typed accessor here so the string
// never leaks past this file, and so the BOUNDS live in one place. A console
// input that only checks the range in the browser is a courtesy; this is the
// rule.

// PlatformSettingStore persists operator-set values. Nil = this deployment has
// no store (no DB), and every accessor then returns its default.
type PlatformSettingStore interface {
	GetSetting(ctx context.Context, key string) (string, bool, error)
	SetSetting(ctx context.Context, key, value string) error
}

// SettingConnRecordRetentionDays is how long the data-plane audit trail is kept.
const SettingConnRecordRetentionDays = "conn_record_retention_days"

// Retention bounds. The floor is 1 because "0 days" is not a retention setting,
// it is turning the feature off — and there is a separate switch for that, so
// letting 0 mean off here would give two ways to say one thing that a reader
// then has to reconcile.
//
// The ceiling is a product decision, not a technical one: an access trail is a
// record of who works with whom, and the longer it is kept the more it becomes
// a liability of its own. 180 days covers the audit questions anybody actually
// asks and stops "forever" from being reachable by typing a big number.
const (
	MinConnRecordRetentionDays = 1
	MaxConnRecordRetentionDays = 180
	// DefaultConnRecordRetentionDays is what a deployment keeps until somebody
	// decides otherwise. Long enough for the audit questions people actually
	// ask, short enough that "we never got round to it" is not "forever".
	DefaultConnRecordRetentionDays = 90
)

// ClampConnRecordRetentionDays brings a requested value inside the bounds and
// reports whether it had to. Callers use the bool to tell the operator what was
// actually stored — silently storing something other than what was typed is how
// a setting comes to mean the opposite of what the page shows.
func ClampConnRecordRetentionDays(n int) (int, bool) {
	switch {
	case n < MinConnRecordRetentionDays:
		return MinConnRecordRetentionDays, true
	case n > MaxConnRecordRetentionDays:
		return MaxConnRecordRetentionDays, true
	default:
		return n, false
	}
}

// ConnRecordRetentionDays returns the operator-set retention, or def when
// nothing is stored.
//
// A stored value that does not parse falls back to def rather than to "keep
// forever": the failure mode of a retention setting has to be keeping LESS than
// intended, never more.
func (c *Coordinator) ConnRecordRetentionDays(ctx context.Context) int {
	def := c.ConnRecordRetentionDefaultDays
	if def == 0 {
		def = DefaultConnRecordRetentionDays
	}
	def, _ = ClampConnRecordRetentionDays(def)
	if c.PlatformSettings == nil {
		return def
	}
	raw, ok, err := c.PlatformSettings.GetSetting(ctx, SettingConnRecordRetentionDays)
	if err != nil || !ok || raw == "" {
		return def
	}
	n, perr := strconv.Atoi(raw)
	if perr != nil {
		return def
	}
	out, _ := ClampConnRecordRetentionDays(n)
	return out
}

// SetConnRecordRetentionDays stores the retention, clamped. Returns what was
// actually stored.
func (c *Coordinator) SetConnRecordRetentionDays(ctx context.Context, n int) (int, error) {
	if c.PlatformSettings == nil {
		return 0, fmt.Errorf("core: this deployment keeps no platform settings")
	}
	out, _ := ClampConnRecordRetentionDays(n)
	if err := c.PlatformSettings.SetSetting(ctx, SettingConnRecordRetentionDays, strconv.Itoa(out)); err != nil {
		return 0, fmt.Errorf("core: store retention: %w", err)
	}
	return out, nil
}
