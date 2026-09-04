package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The mesh meter must book DELTAS per peer and survive the per-session counter
// reset (a peer's rx+tx restarts at 0 on every mesh reconnect), exactly like the
// tunnel meter — otherwise a reconnect would double-count or lose a day's bytes.
// It must also split each peer's delta into relay vs direct by the peer's current
// path, so the overview can show 中继 / 直连 apart (direct is never billed).
func TestMeshUsageMeter_DeltasResetsAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mesh-usage.json")
	m := newMeshUsageMeter(path)
	// Use the real "today": today()/month()/daily() read time.Now(), so the sample
	// time has to land in the same day bucket they look up.
	now := time.Now()

	// First sample: 100 bytes across two peers with no path → relay bucket.
	m.sample([]meshPeerBytes{{Key: "a", Bytes: 60}, {Key: "b", Bytes: 40}}, now)
	if got := m.today(); got.Relay != 100 || got.Direct != 0 {
		t.Fatalf("first sample: today=%+v want {Relay:100 Direct:0}", got)
	}
	// Growth: a=150 (+90), b=40 (+0) → +90 relay.
	m.sample([]meshPeerBytes{{Key: "a", Bytes: 150}, {Key: "b", Bytes: 40}}, now)
	if got := m.today(); got.Relay != 190 {
		t.Fatalf("growth: today.Relay=%d want 190", got.Relay)
	}
	// Reset: a drops to 30 (mesh reconnect) → the new run counts from 0 (+30).
	m.sample([]meshPeerBytes{{Key: "a", Bytes: 30}}, now)
	if got := m.today(); got.Relay != 220 {
		t.Fatalf("reset: today.Relay=%d want 220 (count the fresh run from 0)", got.Relay)
	}

	// A DIRECT-path peer's delta lands in the direct bucket, not relay.
	m.sample([]meshPeerBytes{{Key: "a", Bytes: 30}, {Key: "c", Bytes: 500, Path: meshPathDirect}}, now)
	if got := m.today(); got.Relay != 220 || got.Direct != 500 {
		t.Fatalf("direct path: today=%+v want {Relay:220 Direct:500}", got)
	}

	// Persistence: a fresh meter on the same file sees the same split.
	m2 := newMeshUsageMeter(path)
	if got := m2.today(); got.Relay != 220 || got.Direct != 500 {
		t.Fatalf("reloaded: today=%+v want {Relay:220 Direct:500}", got)
	}

	// daily() fills gaps with 0, ends on today, and carries the split.
	days := m2.daily(7)
	if len(days) != 7 {
		t.Fatalf("daily(7) returned %d rows, want 7", len(days))
	}
	if last := days[6]; last.Date != now.Format("2006-01-02") {
		t.Errorf("daily last day = %q, want today %q", last.Date, now.Format("2006-01-02"))
	}
	if last := days[6]; last.Relay != 220 || last.Direct != 500 {
		t.Errorf("daily last day split = {%d,%d}, want {220,500}", last.Relay, last.Direct)
	}
}

// A pre-split on-disk file was flat {"date": bytes}. Loading it must not lose the
// history: every legacy day migrates into the relay (billed) bucket.
func TestMeshUsageMeter_MigratesFlatFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mesh-usage.json")
	if err := os.WriteFile(path, []byte(`{"2026-08-24":1234}`), 0o600); err != nil {
		t.Fatal(err)
	}
	m := newMeshUsageMeter(path)
	if d := m.days["2026-08-24"]; d == nil || d.Relay != 1234 || d.Direct != 0 {
		t.Fatalf("migrated day = %+v, want {Relay:1234 Direct:0}", d)
	}
}
