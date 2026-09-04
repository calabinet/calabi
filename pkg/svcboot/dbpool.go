package svcboot

import (
	"database/sql"
	"os"
	"strconv"
	"strings"
	"time"
)

// Connection-pool defaults applied to every stateful svc's *sql.DB.
//
// Why this exists: Go's database/sql defaults MaxOpenConns to 0 — i.e.
// UNLIMITED. A burst of slow queries (or a stuck downstream) can then open
// backend connections without bound and exhaust PostgreSQL's
// max_connections, taking down every svc at once. Capping each svc makes
// the global connection count a known quantity
// (svc_count × replicas × MaxOpenConns) instead of "theoretically
// infinite".
//
// Sized for the current ~5k-client scale: 20 open is ample headroom over the ~30-50 steady-state
// active connections while bounding the worst case. Idle 5 keeps a small
// warm pool without pinning 20 idle backends per svc. Lifetime 30m rotates
// connections so a PG failover / DNS change is picked up without a restart.
const (
	defaultMaxOpenConns    = 20
	defaultMaxIdleConns    = 5
	defaultConnMaxLifetime = 30 * time.Minute
)

// ApplyDBPool sets connection-pool limits on db, resolving each knob from
// the environment with a two-level override chain:
//
//	<PREFIX>_MAX_OPEN_CONNS    per-svc override (e.g. IDENTITY_SVC_MAX_OPEN_CONNS)
//	CALABI_MAX_OPEN_CONNS      global override for all svcs
//	(built-in default)         20 / 5 / 30m
//
// Same pattern for MAX_IDLE_CONNS (int) and CONN_MAX_LIFETIME (Go
// duration, e.g. "30m"; "0" = no limit). prefix is the svc's DB-DSN env
// prefix (e.g. "IDENTITY_SVC"); pass "" to consult only the global +
// default.
//
// Intended for PostgreSQL. SQLite callers can skip it (single-writer
// store) — it's harmless but pointless there. No-op if db is nil.
//
// Setting MAX_OPEN_CONNS=0 is a valid escape hatch back to the old
// unlimited behaviour (SetMaxOpenConns(0) means unlimited).
func ApplyDBPool(db *sql.DB, prefix string) {
	if db == nil {
		return
	}
	db.SetMaxOpenConns(poolInt(prefix, "MAX_OPEN_CONNS", defaultMaxOpenConns))
	db.SetMaxIdleConns(poolInt(prefix, "MAX_IDLE_CONNS", defaultMaxIdleConns))
	db.SetConnMaxLifetime(poolDur(prefix, "CONN_MAX_LIFETIME", defaultConnMaxLifetime))
}

func poolInt(prefix, key string, def int) int {
	if prefix != "" {
		if v, ok := envInt(prefix + "_" + key); ok {
			return v
		}
	}
	if v, ok := envInt("CALABI_" + key); ok {
		return v
	}
	return def
}

func poolDur(prefix, key string, def time.Duration) time.Duration {
	if prefix != "" {
		if v, ok := envDur(prefix + "_" + key); ok {
			return v
		}
	}
	if v, ok := envDur("CALABI_" + key); ok {
		return v
	}
	return def
}

// envInt reads a non-negative int env var. 0 is valid (the documented
// "unlimited" escape hatch). Returns ok=false on empty / unparseable /
// negative so the caller falls through to the next override level.
func envInt(name string) (int, bool) {
	s := strings.TrimSpace(os.Getenv(name))
	if s == "" {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// envDur reads a Go duration env var (e.g. "30m", "0"). 0 = no limit.
func envDur(name string) (time.Duration, bool) {
	s := strings.TrimSpace(os.Getenv(name))
	if s == "" {
		return 0, false
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, false
	}
	return d, true
}
