package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
)

// heldFor is how long a test keeps the write lock while it watches the other
// writers. Long enough for each of them to have reached the lock; a writer that
// is not going to wait has failed by then.
const heldFor = 200 * time.Millisecond

// A SQLite file opened the way Open opens it takes concurrent writers one at a
// time instead of failing the second with SQLITE_BUSY. That failure was seen in
// a self-hosted coordinator at startup; it can hit any write, a device's
// registration included.
//
// One connection holds the write lock until the others have been seen waiting
// for it, then lets go. Each of them then waits for a handful of commits at
// most, whatever the disk. Pushing hundreds of commits through instead measures
// the disk: SQLite's waiters poll, nothing queues them, and the one that keeps
// losing sits out its whole busy timeout once the commits ahead of it add up
// to that.
func TestSQLiteFileTakesConcurrentWriters(t *testing.T) {
	driver, _, dsn := splitDSN("sqlite:" + filepath.Join(t.TempDir(), "coord.db"))
	db, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT)`); err != nil {
		t.Fatal(err)
	}
	holder, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err := holder.Exec(`INSERT INTO t (v) VALUES ('holder')`); err != nil {
		t.Fatal(err)
	}

	// Both shapes the store writes in: a single statement, and a transaction.
	const writers = 4
	started := make(chan struct{}, writers)
	done := make(chan error, writers)
	for w := 0; w < writers; w++ {
		go func(w int) {
			started <- struct{}{}
			if w%2 == 0 {
				_, err := db.Exec(`INSERT INTO t (v) VALUES (?)`, w)
				done <- err
				return
			}
			tx, err := db.Begin()
			if err != nil {
				done <- err
				return
			}
			if _, err := tx.Exec(`INSERT INTO t (v) VALUES (?)`, w); err != nil {
				_ = tx.Rollback()
				done <- err
				return
			}
			done <- tx.Commit()
		}(w)
	}
	for w := 0; w < writers; w++ {
		<-started
	}
	select {
	case err := <-done:
		t.Fatalf("a write returned while another connection held the write lock (err: %v), want it to wait its turn", err)
	case <-time.After(heldFor):
	}
	if err := holder.Commit(); err != nil {
		t.Fatal(err)
	}
	for w := 0; w < writers; w++ {
		if err := <-done; err != nil {
			t.Fatalf("a concurrent write failed: %v", err)
		}
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM t`).Scan(&n); err != nil || n != writers+1 {
		t.Fatalf("rows = %d (%v), want %d", n, err, writers+1)
	}
}

// A transaction that reads before it writes waits for the write lock like any
// other writer. Begun the default (deferred) way it asks for that lock at its
// first write, already holding a read lock, and SQLite refuses that step at
// once when another connection is writing — the busy timeout does not cover it.
// ReplaceTunnels is such a transaction: a device's tunnel report failed with
// SQLITE_BUSY whenever it overlapped another write.
func TestSQLiteFileTransactionWaitsForAnotherWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coord.db")
	s, err := Open("sqlite:" + path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	// Another connection in the middle of a write.
	other, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	writing, err := other.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer writing.Close()
	if _, err := writing.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		done <- s.ReplaceTunnels(ctx, 1, 7, []core.Tunnel{{Name: "photos", Type: "http", Status: "online"}}, time.Now())
	}()
	<-started
	select {
	case err := <-done:
		t.Fatalf("ReplaceTunnels returned while another connection was writing (err: %v), want it to wait for the write lock", err)
	case <-time.After(heldFor):
	}
	if _, err := writing.ExecContext(ctx, `COMMIT`); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("ReplaceTunnels behind another writer: %v", err)
	}
	got, err := s.ListTunnels(ctx, 1)
	if err != nil || len(got) != 1 || got[0].Name != "photos" {
		t.Fatalf("tunnels = %v (%v), want the one reported", got, err)
	}
}
