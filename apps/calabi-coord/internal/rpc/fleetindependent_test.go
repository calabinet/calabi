package rpc

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"
)

// A fixed open-loop workload. Randomness affects only synthetic operations,
// never device keys, proofs, authorization or production retry policy.
type neighborJob struct {
	Offset       time.Duration
	Service, Row int
	Write        bool
}

func neighborSchedule(rate, millis int, seed int64) ([]neighborJob, string) {
	n := rate * millis / 1000
	jobs := make([]neighborJob, n)
	rng := rand.New(rand.NewSource(seed))
	permutation := rng.Perm(n)
	for i := range jobs {
		jobs[i] = neighborJob{Offset: time.Duration(i) * time.Second / time.Duration(rate), Service: i % 4, Row: rng.Intn(10000) + 1}
	}
	for _, i := range permutation[:n/4] {
		jobs[i].Write = true
	}
	b, _ := json.Marshal(jobs)
	sum := sha256.Sum256(b)
	return jobs, hex.EncodeToString(sum[:])
}

type fleetProcessPoint struct {
	Millis float64 `json:"ms"`
	CPU    float64 `json:"cpu_seconds"`
	GCs    uint32  `json:"gc_count"`
	Pause  float64 `json:"gc_pause_ms"`
	Alloc  uint64  `json:"allocated_bytes"`
	Heap   uint64  `json:"heap_bytes"`
}
type fleetProcessTrace struct {
	done, exited chan struct{}
	once         sync.Once
	rows         []fleetProcessPoint
	started      time.Time
	cpu          float64
	mem          runtime.MemStats
}

func startFleetProcessTrace() *fleetProcessTrace {
	p := &fleetProcessTrace{done: make(chan struct{}), exited: make(chan struct{}), started: time.Now()}
	p.cpu, _ = performanceProcessUsage()
	runtime.ReadMemStats(&p.mem)
	sample := func() {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		cpu, _ := performanceProcessUsage()
		p.rows = append(p.rows, fleetProcessPoint{float64(time.Since(p.started)) / float64(time.Millisecond), cpu - p.cpu, m.NumGC - p.mem.NumGC, float64(m.PauseTotalNs-p.mem.PauseTotalNs) / 1e6, m.TotalAlloc - p.mem.TotalAlloc, m.HeapAlloc})
	}
	go func() {
		defer close(p.exited)
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				sample()
			case <-p.done:
				sample()
				return
			}
		}
	}()
	return p
}
func (p *fleetProcessTrace) stop() map[string]any {
	p.once.Do(func() { close(p.done) })
	<-p.exited
	return map[string]any{"pid": os.Getpid(), "samples": p.rows, "total": p.rows[len(p.rows)-1]}
}

type neighborSample struct {
	Write                            bool
	Service                          int
	Bin                              int
	Lag, Acquire, SQL, Commit, Total float64
	Begin, Update, Audit             float64
	Error                            bool
	FinishedInWindow                 bool
}

func neighborQuantiles(values []float64) map[string]any {
	sort.Float64s(values)
	q := func(p float64) float64 {
		if len(values) == 0 {
			return 0
		}
		return values[int(math.Ceil(float64(len(values))*p))-1]
	}
	total := 0.0
	for _, v := range values {
		total += v
	}
	return map[string]any{"count": len(values), "total_ms": total, "p50_ms": q(.5), "p95_ms": q(.95), "p99_ms": q(.99), "max_ms": q(1)}
}
func neighborPools(t testing.TB, ctx context.Context) []*sql.DB {
	t.Helper()
	if os.Getenv("CALABI_FLEET_PG_DSN") == "" {
		t.Fatal("independent workload requires isolated PostgreSQL")
	}
	var pools []*sql.DB
	for i := 0; i < 4; i++ {
		db, _ := fleetDatabaseNamed(t, ctx, "fleet-background")
		db.SetMaxOpenConns(20)
		db.SetMaxIdleConns(5)
		t.Cleanup(func() { db.Close() })
		if _, err := db.ExecContext(ctx, `CREATE TABLE load_rows (tenant integer NOT NULL,id integer NOT NULL,value bigint NOT NULL DEFAULT 0,payload text NOT NULL,PRIMARY KEY(tenant,id)); CREATE TABLE load_audit(tenant integer,id integer,value bigint); INSERT INTO load_rows(tenant,id,payload) SELECT 1,g,repeat('x',512) FROM generate_series(1,10000) g`); err != nil {
			t.Fatal(err)
		}
		pools = append(pools, db)
	}
	return pools
}
func runNeighborWindow(ctx context.Context, pools []*sql.DB, start time.Time, rate, millis int, seed int64) map[string]any {
	if err := flushFleetBackendStats(ctx, pools); err != nil {
		return map[string]any{"error": "backend statistics flush failed"}
	}
	observer, err := startFleetPGObserver(ctx, start)
	if err != nil {
		return map[string]any{"error": "PostgreSQL observer startup failed: " + err.Error()}
	}
	jobs, hash := neighborSchedule(rate, millis, seed)
	before := make([]sql.DBStats, 4)
	for i, db := range pools {
		before[i] = db.Stats()
	}
	if wait := time.Until(start); wait > 0 {
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
		}
	}
	trace := startFleetProcessTrace()
	var mu sync.Mutex
	var samples []neighborSample
	dropped := 0
	var wg sync.WaitGroup
	queues := make([]chan neighborJob, 4)
	end := start.Add(time.Duration(millis) * time.Millisecond)
	for service, db := range pools {
		queue := make(chan neighborJob, 64)
		queues[service] = queue
		for worker := 0; worker < 16; worker++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for job := range queue {
					planned := start.Add(job.Offset)
					actual := time.Now()
					sample := neighborSample{Write: job.Write, Service: job.Service, Bin: int(job.Offset / (100 * time.Millisecond)), Lag: float64(actual.Sub(planned)) / 1e6}
					request, cancel := context.WithDeadline(ctx, planned.Add(2*time.Second))
					acquire := time.Now()
					conn, err := db.Conn(request)
					sample.Acquire = float64(time.Since(acquire)) / 1e6
					if err == nil {
						sqlStart := time.Now()
						if !job.Write {
							var value int64
							err = conn.QueryRowContext(request, "SELECT value FROM load_rows WHERE tenant=$1 AND id=$2", 1, job.Row).Scan(&value)
						} else {
							var tx *sql.Tx
							step := time.Now()
							tx, err = conn.BeginTx(request, nil)
							sample.Begin = float64(time.Since(step)) / 1e6
							if err == nil {
								step = time.Now()
								_, err = tx.ExecContext(request, "UPDATE load_rows SET value=value+1 WHERE tenant=$1 AND id=$2", 1, job.Row)
								sample.Update = float64(time.Since(step)) / 1e6
								if err == nil {
									step = time.Now()
									_, err = tx.ExecContext(request, "INSERT INTO load_audit(tenant,id,value) VALUES($1,$2,$3)", 1, job.Row, int64(job.Offset/time.Millisecond))
									sample.Audit = float64(time.Since(step)) / 1e6
								}
								if err == nil {
									commit := time.Now()
									err = tx.Commit()
									sample.Commit = float64(time.Since(commit)) / 1e6
								} else {
									_ = tx.Rollback()
								}
							}
						}
						sample.SQL = float64(time.Since(sqlStart)) / 1e6
						_ = conn.Close()
					}
					cancel()
					finished := time.Now()
					sample.Total = float64(finished.Sub(planned)) / 1e6
					sample.Error = err != nil
					sample.FinishedInWindow = !finished.After(end)
					mu.Lock()
					samples = append(samples, sample)
					mu.Unlock()
				}
			}()
		}
	}
	for _, job := range jobs {
		timer := time.NewTimer(time.Until(start.Add(job.Offset)))
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
		}
		if ctx.Err() != nil {
			dropped++
			continue
		}
		select {
		case queues[job.Service] <- job:
		default:
			dropped++
		}
	}
	for _, q := range queues {
		close(q)
	}
	wg.Wait()
	if wait := time.Until(end); wait > 0 {
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
		}
	}
	process := trace.stop()
	elapsed := float64(time.Since(start)) / 1e6
	flushErr := flushFleetBackendStats(ctx, pools)
	pg := observer.stop()
	if flushErr != nil && pg != nil {
		pg["errors"] = append(pg["errors"].([]string), "backend statistics flush failed")
	}
	groups := map[string]any{}
	for _, kind := range []string{"read", "write"} {
		var lag, acquire, execution, commit, total, begins, updates, audits []float64
		errors, within := 0, 0
		for _, s := range samples {
			if s.Write != (kind == "write") {
				continue
			}
			lag = append(lag, s.Lag)
			acquire = append(acquire, s.Acquire)
			execution = append(execution, s.SQL)
			commit = append(commit, s.Commit)
			begins = append(begins, s.Begin)
			updates = append(updates, s.Update)
			audits = append(audits, s.Audit)
			total = append(total, s.Total)
			if s.Error {
				errors++
			}
			if s.FinishedInWindow {
				within++
			}
		}
		groups[kind] = map[string]any{"schedule_lag": neighborQuantiles(lag), "connection_acquire": neighborQuantiles(acquire), "sql_including_commit": neighborQuantiles(execution), "begin": neighborQuantiles(begins), "update": neighborQuantiles(updates), "audit": neighborQuantiles(audits), "commit": neighborQuantiles(commit), "end_to_end": neighborQuantiles(total), "errors": errors, "completed_within_window": within}
	}
	bins := make([]map[string]any, (millis+99)/100)
	for i := range bins {
		var total, writeTotal, writeSQL, writeCommit []float64
		writes := 0
		for _, s := range samples {
			if s.Bin == i {
				total = append(total, s.Total)
				if s.Write {
					writes++
					writeTotal = append(writeTotal, s.Total)
					writeSQL = append(writeSQL, s.SQL)
					writeCommit = append(writeCommit, s.Commit)
				}
			}
		}
		bins[i] = map[string]any{"ms": i * 100, "writes": writes, "latency": neighborQuantiles(total), "write_latency": neighborQuantiles(writeTotal), "write_sql": neighborQuantiles(writeSQL), "write_commit": neighborQuantiles(writeCommit)}
	}
	var poolsResult []map[string]any
	for i, db := range pools {
		now := db.Stats()
		poolsResult = append(poolsResult, map[string]any{"service": i, "wait_count": now.WaitCount - before[i].WaitCount, "wait_ms": float64(now.WaitDuration-before[i].WaitDuration) / 1e6, "max_open": now.MaxOpenConnections, "max_idle_closed": now.MaxIdleClosed - before[i].MaxIdleClosed})
	}
	return map[string]any{"pid": os.Getpid(), "postgres": pg, "seed": seed, "schedule_sha256": hash, "window_ms": millis, "elapsed_ms": elapsed, "target_rps": rate, "scheduled": len(jobs), "completed": len(samples), "dropped": dropped, "cancelled": ctx.Err() != nil, "read_write": groups, "pools": poolsResult, "process": process, "bins_100ms": bins}
}

type neighborCommand struct {
	Epoch int
	Start int64
}
type neighborControl struct {
	t            testing.TB
	ctx          context.Context
	cancel       context.CancelFunc
	dir          string
	cmd          *exec.Cmd
	exited       chan struct{}
	waitErr      error
	once         sync.Once
	pools        []*sql.DB
	epoch        int
	result       map[string]any
	done         chan struct{}
	rate, millis int
	seed         int64
}

func writeNeighborJSON(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err = os.WriteFile(path+".tmp", b, 0600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}
func startNeighborControl(t *testing.T, ctx context.Context, mode string) *neighborControl {
	t.Helper()
	run, cancel := context.WithCancel(ctx)
	n := &neighborControl{t: t, ctx: run, cancel: cancel, rate: fleetInt("CALABI_FLEET_BACKGROUND_RPS", 400, 1, 4000), millis: fleetInt("CALABI_FLEET_WINDOW_MS", 10000, 100, 30000), seed: int64(fleetInt("CALABI_FLEET_SEED", 20261030, 1, 2147483647))}
	if mode == "inline" {
		n.pools = neighborPools(t, ctx)
		t.Cleanup(n.stop)
		return n
	}
	n.dir = t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	n.cmd = exec.Command(exe, "-test.run=^TestFleetIndependentNeighborProcess$", "-test.timeout=10m")
	n.cmd.Env = append(os.Environ(), "CALABI_FLEET_NEIGHBOR_DIR="+n.dir)
	log, err := os.Create(filepath.Join(n.dir, "worker.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	n.cmd.Stdout = log
	n.cmd.Stderr = log
	if err = n.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	n.exited = make(chan struct{})
	go func() { n.waitErr = n.cmd.Wait(); close(n.exited) }()
	t.Cleanup(n.stop)
	if err := n.await(filepath.Join(n.dir, "ready.json"), 30*time.Second); err != nil {
		t.Fatal(err)
	}
	return n
}
func (n *neighborControl) await(path string, limit time.Duration) error {
	deadline := time.Now().Add(limit)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		if time.Now().After(deadline) || n.ctx.Err() != nil {
			return fmt.Errorf("neighbor phase did not complete: %s", filepath.Base(path))
		}
		select {
		case <-n.exited:
			return fmt.Errorf("neighbor worker exited: %v", n.waitErr)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
}
func (n *neighborControl) begin() {
	if n.epoch > 0 {
		if previous := n.snapshot(); previous["error"] != nil {
			return
		}
	}
	n.epoch++
	n.result = nil
	n.done = make(chan struct{})
	start := time.Now().Add(time.Duration(fleetInt("CALABI_FLEET_ARM_MS", 100, 100, 3000)) * time.Millisecond)
	if n.pools != nil {
		go func() {
			defer close(n.done)
			n.result = runNeighborWindow(n.ctx, n.pools, start, n.rate, n.millis, n.seed)
		}()
	} else {
		if err := writeNeighborJSON(filepath.Join(n.dir, fmt.Sprintf("command-%d.json", n.epoch)), neighborCommand{n.epoch, start.UnixNano()}); err != nil {
			n.result = map[string]any{"error": err.Error()}
			return
		}
	}
	timer := time.NewTimer(time.Until(start))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-n.ctx.Done():
	}
}
func (n *neighborControl) snapshot() map[string]any {
	if n.pools != nil {
		<-n.done
		return n.result
	}
	if n.result != nil {
		return n.result
	}
	path := filepath.Join(n.dir, fmt.Sprintf("result-%d.json", n.epoch))
	if err := n.await(path, time.Duration(n.millis)*time.Millisecond+5*time.Second); err != nil {
		n.result = map[string]any{"error": err.Error()}
		return n.result
	}
	b, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(b, &n.result)
	}
	if err == nil && n.result == nil {
		err = fmt.Errorf("empty neighbor result")
	}
	if err != nil {
		n.result = map[string]any{"error": err.Error()}
	}
	return n.result
}
func (n *neighborControl) stop() {
	n.once.Do(func() {
		n.cancel()
		if n.pools != nil {
			if n.done != nil {
				<-n.done
			}
			return
		}
		_ = os.WriteFile(filepath.Join(n.dir, "stop"), nil, 0600)
		select {
		case <-n.exited:
			if n.waitErr != nil {
				n.t.Errorf("neighbor process: %v", n.waitErr)
			}
		case <-time.After(5 * time.Second):
			_ = n.cmd.Process.Kill()
			<-n.exited
			n.t.Error("neighbor process failed to stop")
		}
	})
}

func TestFleetIndependentNeighborProcess(t *testing.T) {
	dir := os.Getenv("CALABI_FLEET_NEIGHBOR_DIR")
	if dir == "" {
		t.Skip("child process only")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if _, err := os.Stat(filepath.Join(dir, "stop")); err == nil {
					cancel()
					return
				}
			}
		}
	}()
	pools := neighborPools(t, ctx)
	if err := writeNeighborJSON(filepath.Join(dir, "ready.json"), map[string]int{"pid": os.Getpid()}); err != nil {
		t.Fatal(err)
	}
	rate := fleetInt("CALABI_FLEET_BACKGROUND_RPS", 400, 1, 4000)
	millis := fleetInt("CALABI_FLEET_WINDOW_MS", 10000, 100, 30000)
	seed := int64(fleetInt("CALABI_FLEET_SEED", 20261030, 1, 2147483647))
	for epoch := 1; ctx.Err() == nil; epoch++ {
		path := filepath.Join(dir, fmt.Sprintf("command-%d.json", epoch))
		var b []byte
		for ctx.Err() == nil {
			var err error
			b, err = os.ReadFile(path)
			if err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if ctx.Err() != nil {
			return
		}
		var cmd neighborCommand
		if err := json.Unmarshal(b, &cmd); err != nil || cmd.Epoch != epoch {
			t.Fatal("invalid phase command")
		}
		result := runNeighborWindow(ctx, pools, time.Unix(0, cmd.Start), rate, millis, seed)
		if err := writeNeighborJSON(filepath.Join(dir, fmt.Sprintf("result-%d.json", epoch)), result); err != nil {
			t.Fatal(err)
		}
	}
}
