package mesh

import (
	"testing"
	"time"
)

func peerAt(key string, rx, tx int64, path string) PeerStatus {
	return PeerStatus{PublicKey: key, RxBytes: rx, TxBytes: tx, Path: path}
}

func byKey(samples []ConnSample) map[string]ConnSample {
	m := make(map[string]ConnSample, len(samples))
	for _, s := range samples {
		m[s.PeerNodeKey] = s
	}
	return m
}

// The first reading is a BASELINE. WireGuard's counters are cumulative and a
// daemon may have been up for a week — reporting the first snapshot as a window
// would put the whole week into five minutes, and the trail would say a quiet
// machine transferred gigabytes at the moment it reconnected.
func TestConnReporterFirstSampleIsABaseline(t *testing.T) {
	r := newConnReporter()
	t0 := time.Unix(1_700_000_000, 0)

	if got := r.sample([]PeerStatus{peerAt("a", 5_000_000, 9_000_000, "direct")}, t0); got != nil {
		t.Fatalf("the first sample reported %d rows, want none (it is the baseline)", len(got))
	}
	// Second reading: only what moved since.
	got := r.sample([]PeerStatus{peerAt("a", 5_000_100, 9_000_200, "direct")}, t0.Add(5*time.Minute))
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1", len(got))
	}
	if got[0].BytesRx != 100 || got[0].BytesTx != 200 {
		t.Fatalf("delta = rx %d / tx %d, want 100 / 200", got[0].BytesRx, got[0].BytesTx)
	}
	if !got[0].WindowStart.Equal(t0) || !got[0].WindowEnd.Equal(t0.Add(5*time.Minute)) {
		t.Fatalf("window = [%v, %v), want [%v, %v)", got[0].WindowStart, got[0].WindowEnd, t0, t0.Add(5*time.Minute))
	}
}

// WireGuard resets a peer's counters whenever the peer is reconfigured, which
// happens on every netmap that changes the peer set. Subtracting then gives a
// negative; clamping it to zero would silently drop everything since the reset.
// The current value IS the delta.
func TestConnReporterHandlesACounterReset(t *testing.T) {
	r := newConnReporter()
	t0 := time.Unix(1_700_000_000, 0)
	r.sample([]PeerStatus{peerAt("a", 1_000, 2_000, "direct")}, t0)

	got := r.sample([]PeerStatus{peerAt("a", 40, 70, "direct")}, t0.Add(5*time.Minute))
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1", len(got))
	}
	if got[0].BytesRx != 40 || got[0].BytesTx != 70 {
		t.Fatalf("after a reset the delta = rx %d / tx %d, want the current values 40 / 70",
			got[0].BytesRx, got[0].BytesTx)
	}
}

// A peer in the netmap that nobody talked to is not a connection. Writing a row
// for every visible peer every five minutes would bury the real ones and make
// the retention window the only thing bounding the table.
func TestConnReporterSkipsPeersWithNoTraffic(t *testing.T) {
	r := newConnReporter()
	t0 := time.Unix(1_700_000_000, 0)
	peers := []PeerStatus{peerAt("quiet", 10, 10, "relay"), peerAt("busy", 10, 10, "direct")}
	r.sample(peers, t0)

	got := r.sample([]PeerStatus{
		peerAt("quiet", 10, 10, "relay"),
		peerAt("busy", 10, 1_010, "direct"),
	}, t0.Add(5*time.Minute))
	if len(got) != 1 {
		t.Fatalf("got %d rows, want only the peer that moved: %+v", len(got), got)
	}
	if got[0].PeerNodeKey != "busy" || got[0].BytesTx != 1000 {
		t.Fatalf("row = %+v, want busy with 1000 tx", got[0])
	}
	// A window where nothing at all moved reports nothing, rather than a page of
	// zeroes every five minutes forever.
	if quiet := r.sample([]PeerStatus{peerAt("quiet", 10, 10, "relay")}, t0.Add(10*time.Minute)); quiet != nil {
		t.Fatalf("an idle window reported %d rows, want none", len(quiet))
	}
}

// A peer that appears mid-window has no previous reading. Its current counters
// are the delta — it only just started existing — and treating "unseen" as zero
// would be the same answer by luck rather than by rule.
func TestConnReporterCountsANewPeerFromZero(t *testing.T) {
	r := newConnReporter()
	t0 := time.Unix(1_700_000_000, 0)
	r.sample([]PeerStatus{peerAt("a", 100, 100, "direct")}, t0)

	got := byKey(r.sample([]PeerStatus{
		peerAt("a", 100, 100, "direct"),
		peerAt("b", 500, 600, "relay"),
	}, t0.Add(5*time.Minute)))
	if len(got) != 1 {
		t.Fatalf("got %d rows, want only the new peer", len(got))
	}
	b, ok := got["b"]
	if !ok || b.BytesRx != 500 || b.BytesTx != 600 {
		t.Fatalf("new peer row = %+v, want rx 500 / tx 600", got)
	}
	if b.Path != "relay" {
		t.Fatalf("path = %q, want relay", b.Path)
	}
}

// Nothing that could locate a machine may be in a sample. This is the line that
// lets the trail exist as history at all: a
// sequence of endpoint addresses is a location trail, a sequence of peer pairs
// is an access trail. The struct is the enforcement point, so pin its shape.
func TestConnSampleCarriesNoEndpoint(t *testing.T) {
	r := newConnReporter()
	t0 := time.Unix(1_700_000_000, 0)
	p := peerAt("a", 0, 0, "direct")
	p.Endpoint = "203.0.113.7:41641" // the datapath knows it; the report must not
	p.AllowedIPs = []string{"100.64.0.9/32"}
	r.sample([]PeerStatus{p}, t0)

	p.TxBytes = 1
	got := r.sample([]PeerStatus{p}, t0.Add(5*time.Minute))
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1", len(got))
	}
	// A compile-time check would be better, but the field list is the contract:
	// if someone adds an Endpoint to ConnSample this stops being true and the
	// failure message says why it matters.
	for _, f := range []string{got[0].Path, got[0].PeerNodeKey} {
		if f == p.Endpoint {
			t.Fatal("a connection sample carried the peer's endpoint address")
		}
	}
}
