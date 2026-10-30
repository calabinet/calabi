package rpc

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Opt-in diagnostics for the disposable loopback fixture only. No production
// connection, statistics reset, query text or parameters are emitted.
type fleetPGObserver struct {
	db               *sql.DB
	ctx              context.Context
	cancel           context.CancelFunc
	done             chan struct{}
	once             sync.Once
	start            time.Time
	before           map[string]float64
	statementsBefore map[string]float64
	rows             []map[string]any
	errors           []string
	result           map[string]any
}

func fleetObserverDSN(raw string) (string, error) {
	u, err := fleetLoopbackDatabaseURL(raw)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("application_name", "fleet-observer")
	q.Set("default_transaction_read_only", "on")
	q.Set("statement_timeout", "500")
	q.Set("connect_timeout", "2")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func startFleetPGObserver(parent context.Context, start time.Time) (*fleetPGObserver, error) {
	if os.Getenv("CALABI_FLEET_PG_OBSERVE") != "1" {
		return nil, nil
	}
	dsn, err := fleetObserverDSN(os.Getenv("CALABI_FLEET_PG_DSN"))
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	ctx, cancel := context.WithCancel(parent)
	p := &fleetPGObserver{db: db, ctx: ctx, cancel: cancel, start: start, done: make(chan struct{})}
	fail := func(err error) (*fleetPGObserver, error) { cancel(); db.Close(); return nil, err }
	check, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	var ok bool
	err = db.QueryRowContext(check, `SELECT current_setting('track_io_timing')='on' AND current_setting('track_wal_io_timing')='on' AND current_setting('fsync')='on' AND current_setting('synchronous_commit')='on' AND current_setting('full_page_writes')='on'`).Scan(&ok)
	if err != nil {
		return fail(err)
	}
	if !ok {
		return fail(fmt.Errorf("observer requires timing and durability enabled"))
	}
	// Let fixture setup counters flush before the measurement baseline.
	timer := time.NewTimer(1100 * time.Millisecond)
	select {
	case <-timer.C:
	case <-ctx.Done():
		timer.Stop()
		return fail(ctx.Err())
	}
	p.before, err = p.counters()
	if err != nil {
		return fail(err)
	}
	p.statementsBefore, err = p.statements()
	if err != nil {
		return fail(err)
	}
	go func() {
		defer close(p.done)
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				row, err := p.sample()
				if err != nil {
					if ctx.Err() == nil {
						p.errors = append(p.errors, "sample failed")
					}
					return
				}
				p.rows = append(p.rows, row)
			}
		}
	}()
	return p, nil
}
func (p *fleetPGObserver) counters() (map[string]float64, error) {
	ctx, cancel := context.WithTimeout(p.ctx, time.Second)
	defer cancel()
	var lsn, records, bytes, writes, syncs, writeMS, syncMS, xacts, rollback, readMS, writeDBMS, dealloc, checkpoints float64
	err := p.db.QueryRowContext(ctx, `SELECT pg_wal_lsn_diff(pg_current_wal_insert_lsn(),'0/0'),w.wal_records,w.wal_bytes,w.wal_write,w.wal_sync,w.wal_write_time,w.wal_sync_time,d.xact_commit,d.xact_rollback,d.blk_read_time,d.blk_write_time,i.dealloc,b.checkpoints_timed+b.checkpoints_req FROM pg_stat_wal w CROSS JOIN pg_stat_database d CROSS JOIN pg_stat_statements_info i CROSS JOIN pg_stat_bgwriter b WHERE d.datname=current_database()`).Scan(&lsn, &records, &bytes, &writes, &syncs, &writeMS, &syncMS, &xacts, &rollback, &readMS, &writeDBMS, &dealloc, &checkpoints)
	return map[string]float64{"wal_lsn_bytes": lsn, "wal_records": records, "wal_bytes": bytes, "wal_writes": writes, "wal_syncs": syncs, "wal_write_ms": writeMS, "wal_sync_ms": syncMS, "db_commits": xacts, "db_rollbacks": rollback, "db_read_ms": readMS, "db_write_ms": writeDBMS, "statement_dealloc": dealloc, "checkpoints": checkpoints}, err
}
func (p *fleetPGObserver) statements() (map[string]float64, error) {
	ctx, cancel := context.WithTimeout(p.ctx, time.Second)
	defer cancel()
	// Bounded labels are selected on the server; never retrieve query text.
	rows, err := p.db.QueryContext(ctx, `SELECT split_part(upper(ltrim(query)),' ',1), CASE WHEN query ILIKE '%load_rows%' OR query ILIKE '%load_audit%' THEN 'background' WHEN query ILIKE '%mesh_nodes%' THEN 'nodes' WHEN query ILIKE '%mesh_services%' THEN 'services' WHEN query ILIKE '%mesh_settings%' THEN 'settings' ELSE 'other' END,sum(calls),sum(total_exec_time),sum(wal_bytes),sum(shared_blks_dirtied),sum(blk_read_time),sum(blk_write_time) FROM pg_stat_statements WHERE dbid=(SELECT oid FROM pg_database WHERE datname=current_database()) AND query NOT ILIKE '%pg_stat%' AND split_part(upper(ltrim(query)),' ',1) IN ('SELECT','UPDATE','INSERT','BEGIN','COMMIT','ROLLBACK') GROUP BY 1,2`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]float64{}
	for rows.Next() {
		var verb, table string
		var calls, ms, wal, dirty, readMS, writeMS float64
		if err := rows.Scan(&verb, &table, &calls, &ms, &wal, &dirty, &readMS, &writeMS); err != nil {
			return nil, err
		}
		key := verb + "/" + table + "/"
		for k, v := range map[string]float64{"calls": calls, "exec_ms": ms, "wal_bytes": wal, "dirty_blocks": dirty, "read_ms": readMS, "write_ms": writeMS} {
			out[key+k] = v
		}
	}
	return out, rows.Err()
}
func fleetPGDelta(before, after map[string]float64) (map[string]float64, error) {
	tolerance := func(k string) float64 {
		if strings.HasSuffix(k, "_ms") {
			return 0.000001
		}
		return 0
	}
	for k, v := range before {
		if after[k]+tolerance(k) < v {
			return nil, fmt.Errorf("statistics counter reset: %s", k)
		}
	}
	out := map[string]float64{}
	for k, v := range after {
		out[k] = max(0, v-before[k])
	}
	return out, nil
}

func (p *fleetPGObserver) sample() (map[string]any, error) {
	ctx, cancel := context.WithTimeout(p.ctx, time.Second)
	defer cancel()
	rows, err := p.db.QueryContext(ctx, `SELECT application_name, CASE WHEN wait_event_type IS NULL THEN 'running' ELSE wait_event_type||'/'||wait_event END,count(*) FROM pg_stat_activity WHERE datname=current_database() AND application_name IN ('fleet-coord','fleet-background') AND state='active' GROUP BY 1,2`)
	if err != nil {
		return nil, err
	}
	waits := map[string]int{}
	for rows.Next() {
		var app, event string
		var count int
		if err := rows.Scan(&app, &event, &count); err != nil {
			rows.Close()
			return nil, err
		}
		waits[app+"/"+event] = count
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	counters, err := p.counters()
	if err != nil {
		return nil, err
	}
	delta, err := fleetPGDelta(p.before, counters)
	if err != nil {
		return nil, err
	}
	return map[string]any{"ms": float64(time.Since(p.start)) / 1e6, "active_waits": waits, "cumulative": delta}, nil
}
func (p *fleetPGObserver) stop() map[string]any {
	if p == nil {
		return nil
	}
	p.once.Do(func() {
		// Stop sampling, then allow PostgreSQL cumulative backend reports to arrive.
		p.cancel()
		<-p.done
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		p.ctx = ctx
		time.Sleep(1100 * time.Millisecond)
		after, err := p.counters()
		if err != nil {
			p.errors = append(p.errors, "final counters failed")
		}
		delta, e := fleetPGDelta(p.before, after)
		if e != nil {
			p.errors = append(p.errors, e.Error())
		}
		statements, e := p.statements()
		if e != nil {
			p.errors = append(p.errors, "statement statistics failed")
		}
		statementDelta, e := fleetPGDelta(p.statementsBefore, statements)
		if e != nil {
			p.errors = append(p.errors, e.Error())
		}
		if delta["statement_dealloc"] != 0 {
			p.errors = append(p.errors, "statement statistics evicted")
		}
		p.result = map[string]any{"errors": p.errors, "counter_before": p.before, "counter_after": after, "statement_before": p.statementsBefore, "statement_after": statements, "counters": delta, "statements": statementDelta, "samples_100ms": p.rows, "final_stats_grace_ms": 1100, "durability_verified": true}
		p.db.Close()
	})
	return p.result
}

// Force each currently open background backend to report its pending counters.
// Hold distinct connections until all are visited; do not reset shared stats.
func flushFleetBackendStats(ctx context.Context, pools []*sql.DB) error {
	if os.Getenv("CALABI_FLEET_PG_OBSERVE") != "1" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	for _, db := range pools {
		var held []*sql.Conn
		err := func() error {
			defer func() {
				for _, c := range held {
					c.Close()
				}
			}()
			for i, n := 0, db.Stats().OpenConnections; i < n; i++ {
				c, err := db.Conn(ctx)
				if err != nil {
					return err
				}
				held = append(held, c)
				if _, err = c.ExecContext(ctx, "SELECT pg_stat_force_next_flush()"); err != nil {
					return err
				}
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}
