package store

import (
	"database/sql"
	"fmt"
	"strings"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/platform/store/ent"
	"github.com/calabinet/calabi/pkg/svcboot"

	_ "github.com/lib/pq"
	_ "modernc.org/sqlite"
)

// Open returns a Store backed by the given DSN; identical contract to the other
// control-plane svc Open helpers (sqlite for dev/test, postgres for prod).
func Open(dsn string) (*Store, error) {
	driverName, sqlDialect, sqlDSN := splitDSN(dsn)
	db, err := sql.Open(driverName, sqlDSN)
	if err != nil {
		return nil, fmt.Errorf("sql.Open(%s): %w", driverName, err)
	}
	if sqlDialect == dialect.Postgres {
		svcboot.ApplyDBPool(db, "COORD_SVC")
	}
	drv := entsql.OpenDB(sqlDialect, db)
	return New(ent.NewClient(ent.Driver(drv))), nil
}

func splitDSN(dsn string) (driverName, sqlDialect, normalizedDSN string) {
	switch {
	case dsn == "" || dsn == ":memory:":
		return "sqlite", dialect.SQLite, withSQLiteParams("file::memory:?cache=shared")
	case strings.HasPrefix(dsn, "sqlite:"):
		return "sqlite", dialect.SQLite, withSQLiteParams(strings.TrimPrefix(dsn, "sqlite:"))
	case strings.HasPrefix(dsn, "postgres://"), strings.HasPrefix(dsn, "postgresql://"):
		return "postgres", dialect.Postgres, dsn
	default:
		return "postgres", dialect.Postgres, dsn
	}
}

func withSQLiteParams(dsn string) string {
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	if !strings.Contains(dsn, "_pragma=foreign_keys") {
		dsn += sep + "_pragma=foreign_keys(on)"
		sep = "&"
	}
	if !strings.Contains(dsn, "_fk=") {
		dsn += sep + "_fk=1"
		sep = "&"
	}
	// database/sql keeps several connections, and SQLite takes one writer at a
	// time. Without a busy timeout a second writer fails at once with
	// SQLITE_BUSY instead of waiting its turn — seen at startup, when the
	// usage purge ran into another write. A self-hosted coordinator's default
	// store is this file, so a registration must not fail the same way.
	if !strings.Contains(dsn, "busy_timeout") {
		dsn += sep + "_pragma=busy_timeout(10000)"
		sep = "&"
	}
	// The busy timeout covers a connection that holds no lock yet. A
	// transaction begun the default (deferred) way holds a read lock from its
	// first read and asks for the write lock at its first write; if another
	// connection is writing at that point SQLite refuses the step at once with
	// SQLITE_BUSY, without waiting. ReplaceTunnels reads and then writes, so a
	// device's tunnel report failed whenever it overlapped another write.
	// Begun immediate, a transaction takes the write lock up front, where the
	// timeout applies.
	if !strings.Contains(dsn, "_txlock=") {
		dsn += sep + "_txlock=immediate"
	}
	return dsn
}
