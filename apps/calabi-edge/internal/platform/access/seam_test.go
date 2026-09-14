// seam_test.go — the two sides of the listener/platform seam must use the same
// words.
//
// internal/accesslog declares the outcome vocabulary as plain strings (the open
// tree cannot import this package), and this package re-declares it as a typed
// constant and VALIDATES on the way in. That is the right shape, and it is also
// exactly the shape that fails silently: rename one constant on one side and
// every record of that kind is dropped by Note's Valid() check. No build error,
// no log line, just a category of visitor that stops appearing in the console.
//
// RUN: go test./apps/calabi-edge/internal/platform/access/ -run TestSeam -v
package access

import (
	"testing"
	"time"

	"github.com/calabi/calabi/apps/calabi-edge/internal/accesslog"
)

func TestSeamVocabulariesMatch(t *testing.T) {
	// Every word a listener can emit must survive the trip.
	fromListeners := []string{
		accesslog.Allowed,
		accesslog.DeniedIP,
		accesslog.DeniedAuth,
		accesslog.DeniedRate,
	}
	for _, word := range fromListeners {
		if !Outcome(word).Valid() {
			t.Errorf("listeners can emit %q, but this package drops it as unknown", word)
		}
	}

	// And the other direction: nothing this package accepts should be a word no
	// listener can produce, or the table has a dimension value nothing writes.
	known := map[string]bool{}
	for _, w := range fromListeners {
		known[w] = true
	}
	for _, o := range []Outcome{Allowed, DeniedIP, DeniedAuth, DeniedRate} {
		if !known[string(o)] {
			t.Errorf("this package accepts %q, which no listener emits", o)
		}
	}
}

// End to end across the seam: a listener-shaped call through the Sink interface
// lands as a row.
func TestSeamSinkRecords(t *testing.T) {
	rec := New()
	var sink accesslog.Sink = rec
	sink.NoteAccess(7, 42, "203.0.113.5", accesslog.DeniedAuth, at(10))

	rows, _ := rec.Drain()
	if len(rows) != 1 {
		t.Fatalf("got %d rows through the sink, want 1", len(rows))
	}
	if rows[0].Outcome != string(DeniedAuth) || rows[0].VisitorIP != "203.0.113.5" {
		t.Fatalf("row came through wrong: %+v", rows[0])
	}
}

// With no sink installed, Note is inert — that is the community build and the
// "access log off" deployment, and it must not panic on the visitor hot path.
func TestSeamNoSinkInstalled(t *testing.T) {
	accesslog.SetSink(nil)
	accesslog.Note(7, 42, "203.0.113.5", accesslog.Allowed)

	rec := New()
	accesslog.SetSink(rec)
	t.Cleanup(func() { accesslog.SetSink(nil) })
	accesslog.Note(7, 42, "203.0.113.5", accesslog.Allowed)
	rows, _ := rec.Drain()
	if len(rows) != 1 {
		t.Fatalf("after installing a sink got %d rows, want 1", len(rows))
	}

	accesslog.SetSink(nil)
	accesslog.Note(7, 42, "203.0.113.5", accesslog.Allowed)
	if rows, _ := rec.Drain(); len(rows) != 0 {
		t.Fatalf("removing the sink did not stop recording: %+v", rows)
	}
}

var _ accesslog.Sink = (*Recorder)(nil)

var _ = time.Now
