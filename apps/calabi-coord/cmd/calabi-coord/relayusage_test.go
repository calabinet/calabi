package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

type flakySink struct {
	got  []core.RelayUsageRecord
	fail error
}

func (s *flakySink) RecordRelayUsage(_ context.Context, recs []core.RelayUsageRecord) error {
	if s.fail != nil {
		return s.fail
	}
	s.got = append(s.got, recs...)
	return nil
}

func nodeKey(b byte) meshproto.NodeKey {
	var k meshproto.NodeKey
	for i := range k {
		k[i] = b
	}
	return k
}

// fakeRelay serves /usage once per configured batch, draining as the real one
// does: what it hands over, it never hands over again.
func fakeRelay(t *testing.T, token string, batches ...[]core.RelayUsage) *httptest.Server {
	t.Helper()
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var out []core.RelayUsage
		if n < len(batches) {
			out = batches[n]
		}
		n++
		if out == nil {
			out = []core.RelayUsage{}
		}
		_ = json.NewEncoder(w).Encode(struct {
			Deltas []core.RelayUsage `json:"deltas"`
		}{Deltas: out})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func pollerFor(t *testing.T, coord *core.Coordinator, url string) *relayUsagePoller {
	t.Helper()
	// The *Env constants are SUFFIXES now (env.go composes the CALABI_COORD_
	// prefix), so setting the bare name would set a variable nothing reads.
	t.Setenv(envPrefix+"_"+relayUsageTokenEnv, "tok")
	p := newRelayUsagePoller(coord, map[string]string{"lax": url}, slog.Default())
	if p == nil {
		t.Fatal("poller was not created")
	}
	return p
}

func coordWithNodes(t *testing.T, sink core.RelayUsageSink) *core.Coordinator {
	t.Helper()
	c := &core.Coordinator{
		Nodes:          core.NewMemNodeStore(),
		Policy:         core.AllowAllPolicy{},
		IPAM:           core.NewMemIPAM(),
		DERP:           core.StaticDERP{Map: core.DERPMap{Regions: []core.DERPRegion{{Code: "lax"}}}},
		RelayUsageSink: sink,
		Logger:         slog.Default(),
	}
	ctx := context.Background()
	if _, err := c.Register(ctx, core.RegisterInput{Meshnet: 1, Name: "a", NodeKey: nodeKey(1)}); err != nil {
		t.Fatalf("register: %v", err)
	}
	return c
}

func TestPollerDrainsAndAttributes(t *testing.T) {
	sink := &flakySink{}
	coord := coordWithNodes(t, sink)
	srv := fakeRelay(t, "tok", []core.RelayUsage{{Key: nodeKey(1), BytesIn: 100, BytesOut: 10}})

	pollerFor(t, coord, srv.URL).collect(context.Background())

	if len(sink.got) != 1 {
		t.Fatalf("got %d records, want 1", len(sink.got))
	}
	if sink.got[0].Meshnet != 1 || sink.got[0].BytesIn != 100 || sink.got[0].BytesOut != 10 {
		t.Fatalf("unexpected record: %+v", sink.got[0])
	}
	if sink.got[0].Region != "lax" {
		t.Errorf("region = %q, want lax", sink.got[0].Region)
	}
}

// THE property that makes pull safe. Reading the relay already reset its
// counters, so a sink failure after the read must not drop the bytes — they
// exist nowhere else, and losing them silently under-bills in a way nothing
// would ever surface.
func TestPollerHoldsUsageWhenRecordingFails(t *testing.T) {
	sink := &flakySink{fail: errors.New("metering is down")}
	coord := coordWithNodes(t, sink)
	srv := fakeRelay(t, "tok",
		[]core.RelayUsage{{Key: nodeKey(1), BytesIn: 100, BytesOut: 10}}, // first poll, sink fails
		[]core.RelayUsage{{Key: nodeKey(1), BytesIn: 5, BytesOut: 1}},    // second poll, sink recovers
	)
	p := pollerFor(t, coord, srv.URL)
	ctx := context.Background()

	p.collect(ctx)
	if len(sink.got) != 0 {
		t.Fatal("a failing sink recorded something")
	}

	sink.fail = nil
	p.collect(ctx)
	if len(sink.got) != 1 {
		t.Fatalf("got %d records, want 1", len(sink.got))
	}
	// Both rounds, not just the second: 100+5 in, 10+1 out.
	if sink.got[0].BytesIn != 105 || sink.got[0].BytesOut != 11 {
		t.Fatalf("bytes lost across the failure: got %d/%d, want 105/11", sink.got[0].BytesIn, sink.got[0].BytesOut)
	}
	// And once recorded they are not owed any more.
	p.collect(ctx)
	if len(sink.got) != 1 {
		t.Fatalf("usage was recorded twice: %d records", len(sink.got))
	}
}

// A rejected fetch drained nothing, so there is nothing to hold and nothing to
// lose — the next tick simply tries again.
func TestPollerSurvivesARejectedFetch(t *testing.T) {
	sink := &flakySink{}
	coord := coordWithNodes(t, sink)
	srv := fakeRelay(t, "the-other-token", []core.RelayUsage{{Key: nodeKey(1), BytesIn: 100}})

	pollerFor(t, coord, srv.URL).collect(context.Background())
	if len(sink.got) != 0 {
		t.Fatal("recorded usage from a fetch that was rejected")
	}
}

func TestLoadRelayUsageAddrs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "derp-map.json")
	body := `{
	  "home_region": "lax",
	  "regions": [{"code":"lax","nodes":[{"host_name":"r.example","derp_port":3340,"stun_port":3478}]}],
	  "usage_collection": {
	    "lax": "https://r.internal:9200",
	    "bad-scheme": "ftp://nope",
	    "not-a-url": "::::",
	    "blank": ""
	  }
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv("CALABI_COORD_DERP_MAP_FILE", path)

	got := loadRelayUsageAddrs(slog.Default())
	if len(got) != 1 || got["lax"] != "https://r.internal:9200" {
		t.Fatalf("got %v, want only the usable https entry", got)
	}
}

func TestLoadRelayUsageAddrsWithoutAFile(t *testing.T) {
	t.Setenv("CALABI_COORD_DERP_MAP_FILE", "")
	if got := loadRelayUsageAddrs(slog.Default()); len(got) != 0 {
		t.Fatalf("got %v, want nothing to collect", got)
	}
}
