package store

import (
	"database/sql"
	"fmt"
	"strings"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"

	"github.com/calabi/calabi/apps/calabi-coord/internal/platform/store/ent"
	"github.com/calabi/calabi/pkg/svcboot"

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
	}
	return dsn
}
