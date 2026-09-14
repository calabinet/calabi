// access_test.go — the four things that decide whether this table stays a
// bounded audit trail or becomes a liability.
//
// RUN: go test./apps/calabi-edge/internal/platform/access/ -v
package access

import (
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"
)

func at(h int) time.Time {
	return time.Date(2026, 9, 13, h, 30, 0, 0, time.UTC)
}

func TestNoteAggregatesByHourAndOutcome(t *testing.T) {
	r := New()
	r.Note(7, 42, "203.0.113.5", Allowed, at(10))
	r.Note(7, 42, "203.0.113.5", Allowed, at(10))
	r.Note(7, 42, "203.0.113.5", DeniedIP, at(10))
	r.Note(7, 42, "198.51.100.9", Allowed, at(10))
	// A different hour is a different row, or the trail cannot answer "when".
	r.Note(7, 42, "203.0.113.5", Allowed, at(11))

	rows, _ := r.Drain()
	if len(rows) != 4 {
		t.Fatalf("got %d rows, want 4: %+v", len(rows), rows)
	}
	var tenAM, elevenAM int64
	for _, row := range rows {
		switch row.Hour {
		case at(10).Truncate(time.Hour).Unix():
			tenAM += row.Conns
		case at(11).Truncate(time.Hour).Unix():
			elevenAM += row.Conns
		default:
			t.Fatalf("row in an unexpected hour: %+v", row)
		}
	}
	if tenAM != 4 || elevenAM != 1 {
		t.Fatalf("hour totals = %d/%d, want 4/1", tenAM, elevenAM)
	}
}

// Drain hands over a DELTA and resets. Everything downstream is an
// upsert-add, so a recorder that kept its counters would re-add the same
// connections on every flush — the whole table would climb forever off one
// visitor.
func TestDrainResets(t *testing.T) {
	r := New()
	r.Note(7, 42, "203.0.113.5", Allowed, at(10))
	first, _ := r.Drain()
	if n := len(first); n != 1 {
		t.Fatalf("first drain returned %d rows, want 1", n)
	}
	if rows, _ := r.Drain(); len(rows) != 0 {
		t.Fatalf("second drain returned %+v, want nothing", rows)
	}
	r.Note(7, 42, "203.0.113.5", Allowed, at(10))
	rows, _ := r.Drain()
	if len(rows) != 1 || rows[0].Conns != 1 {
		t.Fatalf("after reset got %+v, want a single row of 1", rows)
	}
}

// The cap is what keeps the table's size OUR decision instead of the decision
// of whoever points a scanner at a published tunnel.
func TestVisitorCapFoldsIntoOverflow(t *testing.T) {
	r := New()
	const extra = 50
	for i := 0; i < MaxVisitorsPerTunnelHour+extra; i++ {
		r.Note(7, 42, fmt.Sprintf("203.0.113.%d", i), Allowed, at(10))
	}
	rows, _ := r.Drain()
	// MaxVisitorsPerTunnelHour named rows + exactly one overflow row.
	if len(rows) != MaxVisitorsPerTunnelHour+1 {
		t.Fatalf("got %d rows, want %d named + 1 overflow", len(rows), MaxVisitorsPerTunnelHour)
	}
	var overflow int64
	var total int64
	for _, row := range rows {
		total += row.Conns
		if row.VisitorIP == OverflowIP {
			overflow = row.Conns
		}
	}
	if overflow != extra {
		t.Fatalf("overflow row counts %d, want %d", overflow, extra)
	}
	// Nothing may be LOST to the cap — the connection still happened, we just
	// stop claiming to know which address it came from.
	if total != MaxVisitorsPerTunnelHour+extra {
		t.Fatalf("total conns = %d, want %d — the cap dropped connections",
			total, MaxVisitorsPerTunnelHour+extra)
	}
}

// An address already being counted keeps its own row after the cap is reached.
// Folding a known visitor into overflow mid-hour would make its count wrong
// exactly when someone is looking at it.
func TestCapDoesNotDemoteAnAlreadyNamedVisitor(t *testing.T) {
	r := New()
	r.Note(7, 42, "203.0.113.1", Allowed, at(10)) // named first
	for i := 0; i < MaxVisitorsPerTunnelHour+20; i++ {
		r.Note(7, 42, fmt.Sprintf("198.51.100.%d", i), Allowed, at(10))
	}
	r.Note(7, 42, "203.0.113.1", Allowed, at(10)) // still named?

	drained, _ := r.Drain()
	for _, row := range drained {
		if row.VisitorIP == "203.0.113.1" {
			if row.Conns != 2 {
				t.Fatalf("the first visitor's row counts %d, want 2", row.Conns)
			}
			return
		}
	}
	t.Fatal("the visitor named before the cap lost its own row")
}

// The cap is per tunnel-hour. One noisy tunnel must not spend another one's
// budget, and a new hour starts fresh.
func TestCapIsPerTunnelAndPerHour(t *testing.T) {
	r := New()
	for i := 0; i < MaxVisitorsPerTunnelHour; i++ {
		r.Note(7, 42, "203.0.113."+strconv.Itoa(i), Allowed, at(10))
	}
	// Another tunnel, same hour: gets its own row, not overflow.
	r.Note(7, 99, "9.9.9.9", Allowed, at(10))
	// Same tunnel, next hour: likewise.
	r.Note(7, 42, "8.8.8.8", Allowed, at(11))

	named := map[string]bool{}
	drained, _ := r.Drain()
	for _, row := range drained {
		if row.VisitorIP != OverflowIP {
			named[row.VisitorIP] = true
		}
	}
	if !named["9.9.9.9"] {
		t.Fatal("a second tunnel was charged the first tunnel's visitor budget")
	}
	if !named["8.8.8.8"] {
		t.Fatal("the cap did not reset at the hour boundary")
	}
}

// A proxy with no tunnel row cannot be attributed, and a row nobody can
// attribute answers nobody's question. Dropping beats a giant tunnel_id=0 pile.
func TestUnattributedConnectionsAreDropped(t *testing.T) {
	r := New()
	r.Note(7, 0, "203.0.113.5", Allowed, at(10))
	r.Note(0, 42, "203.0.113.5", Allowed, at(10))
	r.Note(7, 42, "203.0.113.5", "something-else", at(10))
	if rows, _ := r.Drain(); len(rows) != 0 {
		t.Fatalf("recorded %+v, want nothing", rows)
	}
}

// An address that did not come from a socket must not become a row key.
func TestJunkAddressesBecomeOverflow(t *testing.T) {
	r := New()
	r.Note(7, 42, "", Allowed, at(10))
	r.Note(7, 42, "   ", Allowed, at(10))
	long := ""
	for i := 0; i < 200; i++ {
		long += "a"
	}
	r.Note(7, 42, long, Allowed, at(10))

	rows, _ := r.Drain()
	if len(rows) != 1 || rows[0].VisitorIP != OverflowIP || rows[0].Conns != 3 {
		t.Fatalf("got %+v, want one overflow row of 3", rows)
	}
}

// A nil recorder is the "access records switched off" deployment. It must be
// usable without a nil check at every call site, because a missed check would
// be a panic on the visitor hot path.
func TestNilRecorderIsInert(t *testing.T) {
	var r *Recorder
	r.Note(7, 42, "203.0.113.5", Allowed, at(10))
	if rows, _ := r.Drain(); rows != nil {
		t.Fatalf("nil recorder drained %+v", rows)
	}
	if _, n := r.Drain(); n != 0 {
		t.Fatalf("nil recorder overflowed %d", n)
	}
}

// The visitor path is concurrent by definition: one goroutine per accepted
// connection. RUN: go test -race
func TestConcurrentNotes(t *testing.T) {
	r := New()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				r.Note(7, 42, fmt.Sprintf("203.0.113.%d", g), Allowed, at(10))
			}
		}(g)
	}
	wg.Wait()
	var total int64
	drained, _ := r.Drain()
	for _, row := range drained {
		total += row.Conns
	}
	if total != 800 {
		t.Fatalf("counted %d connections, want 800", total)
	}
}
