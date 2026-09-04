// dsn.go — shared database-DSN resolution for every stateful service.
//
// Why a helper instead of every main.go reaching for os.Getenv:
//   - Two-source resolution: each svc lets ops override its own DB via
//     <SVC>_DB_DSN (e.g. IDENTITY_SVC_DB_DSN), AND lets dev set ONE
//     CALABI_DB_DSN for the whole stack at once. Without this helper
//     every main.go duplicates the fallback chain, and people get it
//     wrong when adding a new svc.
//   - The script (scripts/dev/run.ps1) sets CALABI_DB_DSN once when
//     -Postgres / -Dsn / $env:CALABI_DB_DSN is non-empty; the child
//     processes all inherit it and pick it up here.
//   - Production keeps the per-svc override pattern: identity-svc →
//     identity DB, billing-svc → billing DB, etc. Set the specific
//     env var and the shared one is ignored.
package svcboot

import (
	"os"
	"strings"
)

// DBDsn returns the database DSN for the calling service.
//
// Resolution order:
//
//  1. Each service-specific env var IN THE ORDER GIVEN (e.g.
//     "IDENTITY_SVC_DB_DSN"). The first one set + non-empty wins, so prod
//     can point each svc at its own database. Pass none (or "") to skip
//     this step (rare; used by tools that only want the shared fallback).
//  2. CALABI_DB_DSN. The dev / single-DB shortcut.
//  3. Empty string. The caller's store.Open then falls back to in-memory
//     SQLite (the zero-config dev path).
//
// Several names are accepted so a service can RENAME its env var without
// breaking a running deployment: pass the new name first and the old one
// second, and both keep working until the old one is retired. calabi-coord uses
// this for the CALABI_COORD_* rename.
//
// Always trims whitespace; an env var that's set to "   " is treated
// as unset.
func DBDsn(specificEnv ...string) string {
	for _, name := range specificEnv {
		if name == "" {
			continue
		}
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			return v
		}
	}
	return strings.TrimSpace(os.Getenv("CALABI_DB_DSN"))
}
