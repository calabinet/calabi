package rpc

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"os"
	"sort"
	"sync"
	"testing"
	"time"
)

// Synthetic neighboring services use independent pools and schemas. This is
// database contention, not a deployment of identity/billing or their business APIs.
type fleetBackground struct {
	independent               *neighborControl
	mu                        sync.Mutex
	epoch                     uint64
	started                   time.Time
	latencies                 []float64
	completed, errors, missed int
	peakConnections           int
	rate                      int
	cancel                    context.CancelFunc
	wg                        sync.WaitGroup
}

func startFleetBackground(t *testing.T, ctx context.Context) *fleetBackground {
	t.Helper()
	rate := fleetInt("CALABI_FLEET_BACKGROUND_RPS", 0, 0, 4000)
	if rate == 0 {
		return nil
	}
	if mode := os.Getenv("CALABI_FLEET_BACKGROUND_PROCESS"); mode == "separate" || mode == "inline" {
		return &fleetBackground{independent: startNeighborControl(t, ctx, mode)}
	}
	if os.Getenv("CALABI_FLEET_PG_DSN") == "" {
		t.Fatal("background load requires isolated PostgreSQL")
	}
	b := &fleetBackground{rate: rate}
	run, cancel := context.WithCancel(ctx)
	b.cancel = cancel
	t.Cleanup(cancel)
	// Register closure before schema cleanup: stop/join explicitly in the caller.
	var pools []*sql.DB
	for service := 0; service < 4; service++ {
		db, _ := fleetDatabase(t, ctx)
		db.SetMaxOpenConns(20)
		db.SetMaxIdleConns(5)
		pools = append(pools, db)
		t.Cleanup(func() { _ = db.Close() })
		_, err := db.ExecContext(ctx, `CREATE TABLE load_rows (tenant integer NOT NULL, id integer NOT NULL, value bigint NOT NULL DEFAULT 0, payload text NOT NULL, PRIMARY KEY(tenant,id));
CREATE TABLE load_audit (tenant integer NOT NULL, id integer NOT NULL, value bigint NOT NULL);
INSERT INTO load_rows(tenant,id,payload) SELECT 1,g,repeat('x',512) FROM generate_series(1,10000) g`)
		if err != nil {
			t.Fatal(err)
		}
	}
	b.reset()
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-run.Done():
				return
			case <-ticker.C:
			}
			b.mu.Lock()
			epoch := b.epoch
			b.mu.Unlock()
			var count int
			request, release := context.WithTimeout(run, time.Second)
			err := pools[0].QueryRowContext(request, "SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend'").Scan(&count)
			release()
			b.mu.Lock()
			if err == nil && epoch == b.epoch && count > b.peakConnections {
				b.peakConnections = count
			}
			b.mu.Unlock()
		}
	}()
	for service, db := range pools {
		for worker := 0; worker < 16; worker++ {
			b.wg.Add(1)
			go func(db *sql.DB, worker, service int) {
				defer b.wg.Done()
				period := time.Second * 64 / time.Duration(rate)
				next := time.Now().Add(period * time.Duration(service*16+worker) / 64)
				seq := 0
				for {
					timer := time.NewTimer(time.Until(next))
					select {
					case <-run.Done():
						timer.Stop()
						return
					case <-timer.C:
					}
					b.mu.Lock()
					epoch := b.epoch
					b.mu.Unlock()
					request, release := context.WithTimeout(run, 2*time.Second)
					var err error
					if seq%4 != 0 {
						var value int64
						err = db.QueryRowContext(request, "SELECT value FROM load_rows WHERE tenant=$1 AND id=$2", 1, (seq*17+worker)%10000+1).Scan(&value)
					} else {
						var tx *sql.Tx
						tx, err = db.BeginTx(request, nil)
						if err == nil {
							_, err = tx.ExecContext(request, "UPDATE load_rows SET value=value+1 WHERE tenant=$1 AND id=$2", 1, worker+1)
							if err == nil {
								_, err = tx.ExecContext(request, "INSERT INTO load_audit(tenant,id,value) VALUES($1,$2,$3)", 1, worker+1, seq)
							}
							if err == nil {
								err = tx.Commit()
							} else {
								_ = tx.Rollback()
							}
						}
					}
					release()
					elapsed := float64(time.Since(next)) / float64(time.Millisecond)
					next = next.Add(period)
					missed := 0
					for next.Before(time.Now()) {
						missed++
						next = next.Add(period)
					}
					b.mu.Lock()
					if b.epoch == epoch {
						b.completed++
						b.missed += missed
						if err != nil {
							b.errors++
						}
						if len(b.latencies) < 100000 {
							b.latencies = append(b.latencies, elapsed)
						}
					}
					b.mu.Unlock()
					seq++
				}
			}(db, worker, service)
		}
	}
	t.Cleanup(func() {
		b.stop()
		for _, db := range pools {
			_ = db.Close()
		}
	})
	return b
}

func (b *fleetBackground) stop() {
	if b != nil {
		if b.independent != nil {
			b.independent.stop()
			return
		}
		b.cancel()
		b.wg.Wait()
	}
}
func (b *fleetBackground) reset() {
	if b == nil {
		return
	}
	if b.independent != nil {
		b.independent.begin()
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.epoch++
	b.started = time.Now()
	b.latencies = nil
	b.completed = 0
	b.errors = 0
	b.missed = 0
	b.peakConnections = 0
}
func (b *fleetBackground) snapshot() map[string]any {
	if b == nil {
		return nil
	}
	if b.independent != nil {
		return b.independent.snapshot()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	x := append([]float64(nil), b.latencies...)
	sort.Float64s(x)
	q := func(p float64) float64 {
		if len(x) == 0 {
			return 0
		}
		return x[int(math.Ceil(p*float64(len(x))))-1]
	}
	seconds := time.Since(b.started).Seconds()
	return map[string]any{"sampled_pg_connections_peak": b.peakConnections, "target_rps": b.rate, "completed": b.completed, "errors": b.errors, "missed_arrivals": b.missed, "seconds": seconds, "achieved_rps": float64(b.completed) / seconds, "samples": len(x), "p50_ms": q(.5), "p95_ms": q(.95), "p99_ms": q(.99), "max_ms": q(1), "workload": fmt.Sprintf("4 pools 20/5, 64 paced workers, 75%% reads / 25%% update+audit transactions")}
}
