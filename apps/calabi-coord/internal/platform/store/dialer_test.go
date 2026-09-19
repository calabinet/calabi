package store

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

// A SQLite file opened the way Open opens it takes concurrent writers one at a
// time instead of failing the second with SQLITE_BUSY. That failure was seen in
// a self-hosted coordinator at startup; it can hit any write, a device's
// registration included.
func TestSQLiteFileTakesConcurrentWriters(t *testing.T) {
	driver, _, dsn := splitDSN("sqlite:" + filepath.Join(t.TempDir(), "coord.db"))
	db, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(8)
	if _, err := db.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT)`); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				tx, err := db.Begin()
				if err != nil {
					errs <- err
					return
				}
				if _, err := tx.Exec(`INSERT INTO t (v) VALUES (?)`, fmt.Sprintf("%d-%d", w, i)); err != nil {
					_ = tx.Rollback()
					errs <- err
					return
				}
				if err := tx.Commit(); err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("a concurrent write failed: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM t`).Scan(&n); err != nil || n != 8*40 {
		t.Fatalf("rows = %d (%v), want %d", n, err, 8*40)
	}
}
