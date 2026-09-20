// connrecord_optout_test.go — the org's own "keep no connection log" switch.
//
// It exists because some customers are contractually forbidden to retain a
// record of who reached what. That is the customer's obligation to know, not
// something a platform can infer from their plan or their region — guessing
// either way is wrong in a way they pay for.
//
// RUN: go test./apps/calabi-coord/internal/core/ -run TestConnRecordsOptOut -v
package core

import (
	"context"
	"errors"
	"testing"
	"time"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// memConnRecords is the smallest ConnRecordStore that works.
type memConnRecords struct {
	rows []ConnRecord
}

func (m *memConnRecords) AddConnSamples(_ context.Context, recs []ConnRecord) error {
	m.rows = append(m.rows, recs...)
	return nil
}

func (m *memConnRecords) ListConnRecords(_ context.Context, t MeshnetID, _ ConnRecordQuery) ([]ConnRecord, error) {
	var out []ConnRecord
	for _, r := range m.rows {
		if r.MeshnetID == t {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *memConnRecords) PurgeConnRecordsBefore(_ context.Context, _ time.Time) (int, error) {
	return 0, nil
}

func (m *memConnRecords) PurgeConnRecordsOf(_ context.Context, t MeshnetID) (int, error) {
	kept := m.rows[:0]
	n := 0
	for _, r := range m.rows {
		if r.MeshnetID == t {
			n++
			continue
		}
		kept = append(kept, r)
	}
	m.rows = kept
	return n, nil
}

func (m *memConnRecords) RelayBytesByHour(_ context.Context, t MeshnetID, from, to time.Time) (map[time.Time]int64, error) {
	out := map[time.Time]int64{}
	for _, r := range m.rows {
		if r.MeshnetID == t && !r.Hour.Before(from) && r.Hour.Before(to) {
			out[r.Hour] += r.RelayBytesTx
		}
	}
	return out, nil
}

// failingSettings answers every read with an error.
type failingSettings struct{ SettingsStore }

func (failingSettings) GetSettings(context.Context, MeshnetID) (MeshnetSettings, error) {
	return MeshnetSettings{}, errors.New("settings unavailable")
}

func coordWithRecords(t *testing.T) (*Coordinator, *memConnRecords) {
	t.Helper()
	c := newTestCoord()
	recs := &memConnRecords{}
	c.ConnRecords = recs
	c.Settings = NewMemSettingsStore()
	return c, recs
}

func enrollPair(t *testing.T, c *Coordinator) (int64, meshproto.NodeKey) {
	t.Helper()
	ctx := context.Background()
	a, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1)})
	if err != nil {
		t.Fatalf("register a: %v", err)
	}
	if _, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "b", NodeKey: key(2)}); err != nil {
		t.Fatalf("register b: %v", err)
	}
	return a.ID, key(2)
}

func sample(peer meshproto.NodeKey) ConnSample {
	return ConnSample{
		PeerNodeKey: peer,
		WindowStart: time.Now().Add(-5 * time.Minute),
		WindowEnd:   time.Now(),
		BytesTx:     100,
		BytesRx:     200,
		Path:        "direct",
	}
}

func TestConnRecordsOptOutStopsWrites(t *testing.T) {
	c, recs := coordWithRecords(t)
	ctx := context.Background()
	srcID, peer := enrollPair(t, c)

	if n, err := c.RecordConnections(ctx, srcID, []ConnSample{sample(peer)}); err != nil || n != 1 {
		t.Fatalf("setup: stored %d (err %v), want 1", n, err)
	}

	if err := c.UpdateSettings(ctx, 1, MeshnetSettings{ConnRecordsDisabled: true}); err != nil {
		t.Fatalf("turn off: %v", err)
	}
	// Turning it off DELETES what is already there. "Stop collecting" without
	// "delete what you have" leaves "we keep no such records" false for a whole
	// retention window, which is the state the switch exists to prevent.
	if len(recs.rows) != 0 {
		t.Fatalf("turning the log off left %d stored rows", len(recs.rows))
	}
	// And nothing new lands.
	if n, err := c.RecordConnections(ctx, srcID, []ConnSample{sample(peer)}); err != nil || n != 0 {
		t.Fatalf("after opt-out stored %d (err %v), want 0", n, err)
	}
	if len(recs.rows) != 0 {
		t.Fatalf("a report after opt-out wrote %d rows", len(recs.rows))
	}

	// Back on: recording resumes, and the deleted history stays deleted — a new
	// log from this moment, not a restored one.
	if err := c.UpdateSettings(ctx, 1, MeshnetSettings{ConnRecordsDisabled: false}); err != nil {
		t.Fatalf("turn on: %v", err)
	}
	if n, err := c.RecordConnections(ctx, srcID, []ConnSample{sample(peer)}); err != nil || n != 1 {
		t.Fatalf("after opting back in stored %d (err %v), want 1", n, err)
	}
	if len(recs.rows) != 1 {
		t.Fatalf("rows = %d, want 1 (a fresh log, not the old one back)", len(recs.rows))
	}
}

// One org opting out must not touch another's trail.
func TestConnRecordsOptOutIsPerOrg(t *testing.T) {
	c, recs := coordWithRecords(t)
	ctx := context.Background()

	a, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1)})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := c.Register(ctx, RegisterInput{Meshnet: 1, Name: "b", NodeKey: key(2)}); err != nil {
		t.Fatalf("register: %v", err)
	}
	x, err := c.Register(ctx, RegisterInput{Meshnet: 2, Name: "x", NodeKey: key(3)})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := c.Register(ctx, RegisterInput{Meshnet: 2, Name: "y", NodeKey: key(4)}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := c.RecordConnections(ctx, a.ID, []ConnSample{sample(key(2))}); err != nil {
		t.Fatalf("record org1: %v", err)
	}
	if _, err := c.RecordConnections(ctx, x.ID, []ConnSample{sample(key(4))}); err != nil {
		t.Fatalf("record org2: %v", err)
	}
	if len(recs.rows) != 2 {
		t.Fatalf("setup rows = %d, want 2", len(recs.rows))
	}

	if err := c.UpdateSettings(ctx, 1, MeshnetSettings{ConnRecordsDisabled: true}); err != nil {
		t.Fatalf("turn off org1: %v", err)
	}
	if len(recs.rows) != 1 || recs.rows[0].MeshnetID != 2 {
		t.Fatalf("org1 opting out took org2's rows with it: %+v", recs.rows)
	}
	// org2 keeps recording.
	if n, _ := c.RecordConnections(ctx, x.ID, []ConnSample{sample(key(4))}); n != 1 {
		t.Fatalf("org2 stopped recording because org1 opted out")
	}
}

// A settings read that fails must NOT fall back to recording. An org that asked
// us to keep nothing must not start keeping things because a query timed out:
// the cost of the safe direction is a gap in a trail, the cost of the other one
// is holding data somebody is forbidden to hold.
func TestConnRecordsOptOutFailsClosed(t *testing.T) {
	c, recs := coordWithRecords(t)
	ctx := context.Background()
	srcID, peer := enrollPair(t, c)

	c.Settings = failingSettings{}
	n, err := c.RecordConnections(ctx, srcID, []ConnSample{sample(peer)})
	if err == nil {
		t.Fatal("an unreadable settings store let the report through")
	}
	if n != 0 || len(recs.rows) != 0 {
		t.Fatalf("stored %d rows despite not knowing whether this org opted out", len(recs.rows))
	}
}
