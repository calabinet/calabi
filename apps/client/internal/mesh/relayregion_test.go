package mesh

import (
	"log/slog"
	"net/netip"
	"testing"
	"time"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// The picture the console got wrong for want of one field: this node is homed on
// a PLATFORM relay far away, while the peers it talks to are homed on the org's
// OWN relay next door. Each relayed peer is carried by that peer's relay — the
// status must say which relay that is, and whose.
func TestAnnotateNamesTheRelayCarryingEachPeer(t *testing.T) {
	const (
		platform = "edge01-lax.example.net:3340"
		own      = "relay.office.example.net:3340"
	)
	onOwn := meshproto.NodeKey{2}      // homed on the org's relay
	onPlatform := meshproto.NodeKey{3} // homed on the platform's
	nowhere := meshproto.NodeKey{4}    // its region is not in the map
	direct := meshproto.NodeKey{5}     // hole punching found a path
	directDisco := meshproto.DiscoKey{5}

	disco, _ := GenerateDiscoKey()
	ms, err := newMagicSock(disco, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer ms.Close()
	paths := newFakePaths()

	b := testBind()
	b.attach(&fakeRelay{rttTo: map[string]time.Duration{
		own:      4800 * time.Microsecond,
		platform: 187 * time.Millisecond,
	}})
	b.attachDirect(ms, paths)
	b.setPeers(WGConfig{
		RelayByRegion: map[string]string{"us-west": platform, "self-office": own},
		Peers: []WGPeer{
			{PublicKey: onOwn, DERPHome: "self-office"},
			{PublicKey: onPlatform, DERPHome: "us-west"},
			{PublicKey: nowhere, DERPHome: "gone-region"},
			{PublicKey: direct, DiscoKey: directDisco, DERPHome: "self-office"},
		},
	})
	paths.set(directDisco, netip.MustParseAddrPort("192.168.1.23:41641"))

	peers := []PeerStatus{
		{PublicKey: onOwn.String()},
		{PublicKey: onPlatform.String()},
		{PublicKey: nowhere.String()},
		{PublicKey: direct.String()},
	}
	b.annotate(peers, platform) // this node's own home: the platform relay

	want := []struct {
		name, path, endpoint, region string
		relayRTT                     int64
	}{
		{"homed on the org's relay", PathRelay, own, "self-office", 4800},
		{"homed on the platform's", PathRelay, platform, "us-west", 187000},
		// No relay answers for its region, so it rides OUR home — and is labelled
		// with our home's region, because that is the relay actually carrying it.
		{"region not in the map", PathRelay, platform, "us-west", 187000},
		// A direct path is nobody's relay: the region must not survive from the
		// relay it would otherwise have used.
		{"direct", PathDirect, "192.168.1.23:41641", "", 0},
	}
	for i, w := range want {
		p := peers[i]
		if p.Path != w.path || p.Endpoint != w.endpoint || p.RelayRegion != w.region {
			t.Errorf("%s: path=%q endpoint=%q region=%q, want %q %q %q",
				w.name, p.Path, p.Endpoint, p.RelayRegion, w.path, w.endpoint, w.region)
		}
		if w.path == PathRelay && p.RelayRTTMicros != w.relayRTT {
			t.Errorf("%s: relay rtt = %dµs, want %dµs", w.name, p.RelayRTTMicros, w.relayRTT)
		}
	}
}

// The home relay's own leg, which the status reports beside its address. Absent
// (zero) for a relay with no link or no answer yet — never a made-up number.
func TestRelayRTTReportsOnlyMeasuredLinks(t *testing.T) {
	b := testBind()
	if got := b.relayRTT("relay.example.net:3340"); got != 0 {
		t.Fatalf("no relay client attached: rtt = %d, want 0", got)
	}
	b.attach(&fakeRelay{rttTo: map[string]time.Duration{"relay.example.net:3340": 187 * time.Millisecond}})
	if got := b.relayRTT("relay.example.net:3340"); got != 187000 {
		t.Fatalf("rtt = %dµs, want 187000µs", got)
	}
	if got := b.relayRTT("other.example.net:3340"); got != 0 {
		t.Fatalf("a relay we hold no link to: rtt = %d, want 0", got)
	}
	if got := b.relayRTT(""); got != 0 {
		t.Fatalf("no home yet: rtt = %d, want 0", got)
	}
}

// Two regions naming one address is a map nobody should build, but the answer
// must at least be the same on every netmap — not whichever the map iteration
// yielded this time, which would make the console's label flicker.
func TestRelayRegionIsStableWhenRegionsShareAnAddress(t *testing.T) {
	for i := 0; i < 50; i++ {
		b := testBind()
		b.setPeers(WGConfig{RelayByRegion: map[string]string{
			"us-west":    "relay.example.net:3340",
			"self-twin":  "relay.example.net:3340",
			"ap-sg":      "sg.example.net:3340",
			"empty-code": "",
		}})
		if got := b.relayRegion("relay.example.net:3340"); got != "self-twin" {
			t.Fatalf("run %d: region = %q, want the first in sorted order (self-twin)", i, got)
		}
		if got := b.relayRegion(""); got != "" {
			t.Fatalf("an empty address resolved to region %q", got)
		}
	}
}
