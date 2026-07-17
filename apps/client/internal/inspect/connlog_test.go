package inspect

import "testing"

func TestConnectionLog_AddBytesLiveThenEnd(t *testing.T) {
	l := NewConnectionLog(10)
	c := l.Begin("p1", "1.2.3.4")

	// Live deltas while the connection is open accumulate on the row.
	l.AddBytes(c, 100, 0)
	l.AddBytes(c, 0, 50)
	l.AddBytes(c, 64, 16)
	if got := l.Snapshot(); len(got) != 1 || got[0].BytesIn != 164 || got[0].BytesOut != 66 {
		t.Fatalf("live in/out = %d/%d, want 164/66 (%+v)", got[0].BytesIn, got[0].BytesOut, got)
	}
	if got := l.Snapshot()[0]; got.EndedAt != "" {
		t.Fatalf("connection should still be open (no EndedAt), got %q", got.EndedAt)
	}

	// End overwrites with the authoritative totals (== accumulated deltas).
	l.End(c, 164, 66, nil)
	got := l.Snapshot()[0]
	if got.BytesIn != 164 || got.BytesOut != 66 {
		t.Fatalf("after End in/out = %d/%d, want 164/66", got.BytesIn, got.BytesOut)
	}
	if got.EndedAt == "" {
		t.Fatalf("End must stamp EndedAt")
	}

	// No-ops: nil row, zero delta.
	l.AddBytes(nil, 1, 1)
	l.AddBytes(c, 0, 0)
	if g := l.Snapshot()[0]; g.BytesIn != 164 || g.BytesOut != 66 {
		t.Fatalf("no-op AddBytes changed counters: %d/%d", g.BytesIn, g.BytesOut)
	}
}
