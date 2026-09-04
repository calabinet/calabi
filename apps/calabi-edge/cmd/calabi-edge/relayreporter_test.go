package main

import (
	"encoding/json"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/calabi/calabi/pkg/relay"
)

type fakeBus struct {
	mu        sync.Mutex
	published [][]byte
}

func (f *fakeBus) Publish(_ string, payload []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := append([]byte(nil), payload...)
	f.published = append(f.published, cp)
	return nil
}
// Publish is the whole interface now: the reporter takes usagePublisher, not
// eventbus.Bus, so this file links no platform transport package either — the
// export would otherwise pull pkg/eventbus back in through the TEST deps.

func (f *fakeBus) msgs(t *testing.T) []relayUsageMsg {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]relayUsageMsg, 0, len(f.published))
	for _, p := range f.published {
		var m relayUsageMsg
		if err := json.Unmarshal(p, &m); err != nil {
			t.Fatalf("bad payload: %v", err)
		}
		out = append(out, m)
	}
	return out
}

// The reporter re-sends the RUNNING TOTAL for the current minute (metering-svc
// MAX-merges per minute), and resets on a new minute. Getting this wrong either
// loses bytes (publishing raw deltas that overwrite) or double-counts.
func TestRelayUsageReporter_RunningTotalPerMinute(t *testing.T) {
	fb := &fakeBus{}
	r := newRelayUsageReporter(fb, 7, "self-hk-1", slog.Default())
	t0 := time.Date(2026, 8, 25, 10, 30, 5, 0, time.UTC)

	r.record([]relay.UsageDelta{{BytesIn: 100, BytesOut: 10}}, t0)
	r.record([]relay.UsageDelta{{BytesIn: 50, BytesOut: 5}}, t0.Add(20*time.Second)) // same minute
	r.record([]relay.UsageDelta{{BytesIn: 3, BytesOut: 1}}, t0.Add(70*time.Second))  // next minute
	r.record(nil, t0.Add(80*time.Second))                                            // empty drain → no publish

	m := fb.msgs(t)
	if len(m) != 3 {
		t.Fatalf("published %d msgs, want 3 (empty drain must not publish)", len(m))
	}
	// Same minute: second publish carries the ACCUMULATED running total.
	want := []struct {
		in, out int64
	}{{100, 10}, {150, 15}, {3, 1}}
	for i, w := range want {
		if m[i].OrgID != 7 || m[i].Region != "self-hk-1" {
			t.Errorf("msg[%d] org/region = %d/%q, want 7/self-hk-1", i, m[i].OrgID, m[i].Region)
		}
		if m[i].BytesIn != w.in || m[i].BytesOut != w.out {
			t.Errorf("msg[%d] = %d/%d, want %d/%d", i, m[i].BytesIn, m[i].BytesOut, w.in, w.out)
		}
	}
	if m[0].TS != m[1].TS {
		t.Errorf("same-minute publishes have different ts: %d vs %d", m[0].TS, m[1].TS)
	}
	if m[0].TS == m[2].TS {
		t.Errorf("different minutes share ts %d — reset did not change the minute key", m[0].TS)
	}
}

// A platform relay serves many orgs at once: each delta is billed to the meshnet
// its grant proved, one running total PER (org, region). A delta with no meshnet
// (auth off / no grant) is unattributable and must be dropped, not misbilled.
func TestPlatformRelayUsageReporter_PerOrg(t *testing.T) {
	fb := &fakeBus{}
	r := newPlatformRelayUsageReporter(fb, "lax", slog.Default())
	t0 := time.Date(2026, 8, 25, 10, 30, 5, 0, time.UTC)

	r.record([]relay.UsageDelta{
		{Meshnet: 1, BytesIn: 100, BytesOut: 10},
		{Meshnet: 2, BytesIn: 200, BytesOut: 20},
		{Meshnet: 0, BytesIn: 999, BytesOut: 99}, // no grant → unattributable → dropped
	}, t0)

	m := fb.msgs(t)
	if len(m) != 2 {
		t.Fatalf("published %d msgs, want 2 (org 0 must drop)", len(m))
	}
	byOrg := map[int64]relayUsageMsg{}
	for _, x := range m {
		byOrg[x.OrgID] = x
	}
	if _, leaked := byOrg[0]; leaked {
		t.Error("unattributable (meshnet 0) bytes were published")
	}
	if g := byOrg[1]; g.Region != "lax" || g.BytesIn != 100 || g.BytesOut != 10 {
		t.Errorf("org1 = %+v, want region lax 100/10", g)
	}
	if g := byOrg[2]; g.Region != "lax" || g.BytesIn != 200 || g.BytesOut != 20 {
		t.Errorf("org2 = %+v, want region lax 200/20", g)
	}
	if byOrg[1].TS != byOrg[2].TS {
		t.Errorf("same-tick orgs got different ts: %d vs %d", byOrg[1].TS, byOrg[2].TS)
	}

	// Next minute for org 1 only: its bucket resets (not a running total across the
	// boundary), and org 2 — silent this minute — is not re-published.
	r.record([]relay.UsageDelta{{Meshnet: 1, BytesIn: 5, BytesOut: 1}}, t0.Add(70*time.Second))
	m = fb.msgs(t)
	last := m[len(m)-1]
	if last.OrgID != 1 || last.BytesIn != 5 || last.BytesOut != 1 {
		t.Errorf("post-rollover publish = %+v, want org1 5/1 (fresh minute, not accumulated)", last)
	}
	if len(m) != 3 {
		t.Errorf("published %d total, want 3 (org2 not re-sent on a minute it had no traffic)", len(m))
	}
}
