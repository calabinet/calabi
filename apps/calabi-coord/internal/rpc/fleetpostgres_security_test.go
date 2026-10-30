package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
)

func TestFleetObserverRejectsNonDisposableTargets(t *testing.T) {
	for _, raw := range []string{"", "postgres://user:secret@production/prod", "postgres://127.0.0.1/coord", "postgres://192.0.2.1/calabi_mesh_bench", "postgres://127.0.0.1/calabi_mesh_bench?host=production", "postgres://127.0.0.1/calabi_mesh_bench?dbname=coord", "postgres://127.0.0.1/calabi_mesh_bench?options=-csearch_path=public"} {
		_, err := fleetObserverDSN(raw)
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("unsafe DSN accepted or leaked")
		}
	}
}
func TestFleetObserverDetectsCounterReset(t *testing.T) {
	if _, err := fleetPGDelta(map[string]float64{"x": 2}, map[string]float64{"x": 1}); err == nil {
		t.Fatal("reset hidden")
	}
}
func TestFleetObserverReadOnlyAndFailure(t *testing.T) {
	if os.Getenv("CALABI_FLEET_PG_DSN") == "" || os.Getenv("CALABI_FLEET_PG_OBSERVER_TESTS") != "1" || testing.Short() {
		t.Skip("isolated PostgreSQL")
	}
	t.Setenv("CALABI_FLEET_PG_OBSERVE", "1")
	p, err := startFleetPGObserver(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer p.stop()
	_, err = p.db.Exec("CREATE TABLE must_not_exist(id integer)")
	var pgErr *pq.Error
	if !errors.As(err, &pgErr) || pgErr.Code != "25006" {
		t.Fatalf("expected read-only violation, got %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	r := p.stop()
	if len(r["errors"].([]string)) != 0 || len(r["samples_100ms"].([]map[string]any)) == 0 {
		t.Fatal(r)
	}
	p, err = startFleetPGObserver(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p.db.Close()
	r = p.stop()
	if len(r["errors"].([]string)) == 0 {
		t.Fatal("database failure hidden")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if p, err = startFleetPGObserver(ctx, time.Now()); err == nil {
		p.stop()
		t.Fatal("cancel ignored")
	}
}

func TestFleetObserverFixedWindowCounts(t *testing.T) {
	if os.Getenv("CALABI_FLEET_PG_DSN") == "" || os.Getenv("CALABI_FLEET_PG_OBSERVER_TESTS") != "1" || testing.Short() {
		t.Skip("isolated PostgreSQL")
	}
	t.Setenv("CALABI_FLEET_PG_OBSERVE", "1")
	t.Setenv("CALABI_FLEET_ARM_MS", "1500")
	t.Setenv("CALABI_FLEET_BACKGROUND_RPS", "100")
	t.Setenv("CALABI_FLEET_WINDOW_MS", "800")
	n := startNeighborControl(t, context.Background(), "separate")
	defer n.stop()
	n.begin()
	r := n.snapshot()
	if r["error"] != nil {
		t.Fatal(r)
	}
	v, err := normalizeNeighborResult(r)
	if err != nil || v.Completed != 80 || v.Errors != 0 || v.Dropped != 0 {
		t.Fatalf("bad workload %+v %v", v, err)
	}
	var pg struct {
		Errors               []string
		Counters, Statements map[string]float64
	}
	b, err := json.Marshal(r["postgres"])
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &pg); err != nil {
		t.Fatal(err)
	}
	if len(pg.Errors) > 0 || pg.Statements["UPDATE/background/calls"] != 20 || pg.Statements["INSERT/background/calls"] != 20 || pg.Statements["SELECT/background/calls"] != 60 || pg.Counters["wal_lsn_bytes"] <= 0 {
		t.Fatalf("invalid database evidence %+v", pg)
	}
}

func TestFleetObserverFloatAggregationTolerance(t *testing.T) {
	d, err := fleetPGDelta(map[string]float64{"exec_ms": 1}, map[string]float64{"exec_ms": 1 - 1e-12})
	if err != nil || d["exec_ms"] != 0 {
		t.Fatal(d, err)
	}
	if _, err = fleetPGDelta(map[string]float64{"calls": 1}, map[string]float64{}); err == nil {
		t.Fatal("missing counter reset hidden")
	}
}

func TestFleetObserverRejectsMissingWALTiming(t *testing.T) {
	raw := os.Getenv("CALABI_FLEET_PG_DSN")
	if raw == "" || os.Getenv("CALABI_FLEET_PG_OBSERVER_TESTS") != "1" || testing.Short() {
		t.Skip("isolated PostgreSQL")
	}
	t.Setenv("CALABI_FLEET_PG_OBSERVE", "1")
	sep := "?"
	if strings.Contains(raw, "?") {
		sep = "&"
	}
	t.Setenv("CALABI_FLEET_PG_DSN", raw+sep+"track_wal_io_timing=off")
	p, err := startFleetPGObserver(context.Background(), time.Now())
	if err == nil {
		p.stop()
		t.Fatal("missing timing accepted")
	}
	if !strings.Contains(err.Error(), "requires timing") {
		t.Fatal(err)
	}
}
