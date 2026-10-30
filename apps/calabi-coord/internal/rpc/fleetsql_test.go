package rpc

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// Test-only, bounded labels; never retain SQL text, parameters or identities.
// Driver call time includes pool acquisition but excludes subsequent row scanning.
type fleetSQLMetric struct {
	Calls           uint64  `json:"calls"`
	Errors          uint64  `json:"errors"`
	Milliseconds    float64 `json:"milliseconds"`
	MaxMilliseconds float64 `json:"max_milliseconds"`
}
type fleetSQLProfile struct {
	mu      sync.Mutex
	metrics map[string]fleetSQLMetric
}

func fleetSQLLabel(q string) string {
	verb := "other"
	for _, v := range []string{"SELECT", "UPDATE", "INSERT", "DELETE", "BEGIN", "COMMIT", "ROLLBACK"} {
		if strings.HasPrefix(q, v) {
			verb = v
			break
		}
	}
	table := "other"
	for _, t := range []string{"mesh_nodes", "mesh_services", "mesh_settings", "mesh_acls", "mesh_acl_revisions"} {
		if strings.Contains(q, `"`+t+`"`) {
			table = t
			break
		}
	}
	return verb + "/" + table
}
func (p *fleetSQLProfile) start(q string) func(error) {
	if p == nil {
		return func(error) {}
	}
	label, started := fleetSQLLabel(q), time.Now()
	return func(err error) {
		ms := float64(time.Since(started)) / float64(time.Millisecond)
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.metrics == nil {
			p.metrics = make(map[string]fleetSQLMetric)
		}
		m := p.metrics[label]
		m.Calls++
		if err != nil {
			m.Errors++
		}
		m.Milliseconds += ms
		if ms > m.MaxMilliseconds {
			m.MaxMilliseconds = ms
		}
		p.metrics[label] = m
	}
}
func (p *fleetSQLProfile) snapshot() map[string]fleetSQLMetric {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]fleetSQLMetric, len(p.metrics))
	for k, v := range p.metrics {
		out[k] = v
	}
	return out
}

func TestFleetSQLProfileBoundedLabelsAndPhaseIsolation(t *testing.T) {
	old := &fleetSQLProfile{}
	done := old.start(`SELECT * FROM "mesh_nodes" WHERE "node_key" = 'secret'`)
	next := &fleetSQLProfile{}
	done(errors.New("failed"))
	if len(next.snapshot()) != 0 {
		t.Fatal("previous phase leaked")
	}
	m := old.snapshot()["SELECT/mesh_nodes"]
	if m.Calls != 1 || m.Errors != 1 || m.Milliseconds < 0 {
		t.Fatalf("bad metric: %+v", m)
	}
	for _, sql := range []string{"BEGIN", "COMMIT", "ROLLBACK", `UPDATE "mesh_nodes" SET "disco_key" = $1 RETURNING *`, `SELECT secret FROM "unknown_sensitive_table"`} {
		next.start(sql)(nil)
	}
	if len(next.snapshot()) != 5 || next.snapshot()["UPDATE/mesh_nodes"].Calls != 1 || next.snapshot()["SELECT/other"].Calls != 1 {
		t.Fatal("SQL labels not bounded")
	}
}
