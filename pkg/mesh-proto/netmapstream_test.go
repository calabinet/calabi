package meshproto

import (
	"fmt"
	"sync"
	"testing"

	"github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"google.golang.org/protobuf/proto"
)

func TestPeerFingerprintConcurrentUnknownFieldsAndErrors(t *testing.T) {
	var cache PeerFingerprintCache
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m := streamMap(10)
			var e NetMapEncoder
			for j := 0; j < 10; j++ {
				f, next, err := e.NextWithPeerCache(m, &cache)
				if err != nil || (j > 0 && !f.GrantOnly) {
					t.Error("concurrent cache corrupted stream")
				}
				e = next
			}
		}()
	}
	wg.Wait()
	p := streamMap(1).Peers[0]
	a, err := cache.digest(p)
	if err != nil {
		t.Fatal(err)
	}
	p.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
	b, err := cache.digest(p)
	if err != nil || a == b {
		t.Fatal("unknown field omitted")
	}
	p.Name = string([]byte{0xff})
	if _, err := cache.digest(p); err == nil {
		t.Fatal("invalid protobuf cached as success")
	}
}

func TestPeerFingerprintCapacityFallsBackWithoutDroppingPeers(t *testing.T) {
	var cache PeerFingerprintCache
	for i := int64(1); i <= 4100; i++ {
		p := &meshpb.Peer{NodeId: i, Name: "bounded"}
		got, err := cache.digest(p)
		want, _ := mapDigest(p)
		if err != nil || got != want {
			t.Fatal("capacity changed fingerprint")
		}
	}
	if len(cache.peers) != 4096 || cache.bytes > 8<<20 {
		t.Fatal("unbounded cache")
	}
}

func TestSharedPeerFingerprintContentAndStreamIsolation(t *testing.T) {
	var cache PeerFingerprintCache
	var first, second NetMapEncoder
	m := streamMap(100)
	_, first, _ = first.NextWithPeerCache(m, &cache)
	// Sharing public contents must not share the authenticated stream baseline.
	f, _, err := second.NextWithPeerCache(m, &cache)
	if err != nil || f.Delta || f.Sequence != 1 {
		t.Fatal("shared stream baseline")
	}
	// Even an in-place mutation cannot hide behind a cached ID or pointer.
	m.Peers[0].Endpoints[0] = "192.0.2.9:99"
	f, next, err := first.NextWithPeerCache(m, &cache)
	if err != nil || !f.Delta || len(f.Peers) != 1 || f.Peers[0].Endpoints[0] != "192.0.2.9:99" {
		t.Fatal("stale fingerprint")
	}
	// A failed Send discards next: retry must still emit the same upsert.
	retry, _, err := first.NextWithPeerCache(m, &cache)
	if err != nil || !proto.Equal(f, retry) {
		t.Fatal("uncommitted baseline advanced")
	}
	m.Peers[0].FileTransfer = &meshpb.FileTransferInfo{}
	f, next, err = next.NextWithPeerCache(m, &cache)
	if err != nil || len(f.Peers) != 1 {
		t.Fatal("live declaration not observed")
	}
	m.Peers[0].FileTransfer = nil
	f, _, err = next.NextWithPeerCache(m, &cache)
	if err != nil || len(f.Peers) != 1 || f.Peers[0].FileTransfer != nil {
		t.Fatal("expired declaration retained")
	}
}

func streamMap(n int) *meshpb.NetMap {
	m := &meshpb.NetMap{Self: &meshpb.Peer{NodeId: 1, NodeKey: "self"}, FilterEnabled: true, PacketFilter: []*meshpb.FilterRule{{SrcCidrs: []string{"100.64.0.0/10"}}}, RelayGrant: []byte("grant")}
	for i := 0; i < n; i++ {
		m.Peers = append(m.Peers, &meshpb.Peer{NodeId: int64(i + 2), NodeKey: fmt.Sprintf("key-%d", i), Endpoints: []string{"192.168.1.2:12345"}})
	}
	return m
}

func TestNetMapStreamRoundTripAndRevocation(t *testing.T) {
	var e NetMapEncoder
	var d NetMapDecoder
	m := streamMap(100)
	check := func(wantDelta, wantGrant bool) {
		t.Helper()
		f, next, err := e.Next(m)
		if err != nil {
			t.Fatal(err)
		}
		if f.Delta != wantDelta || f.GrantOnly != wantGrant {
			t.Fatalf("unexpected frame: %v", f)
		}
		// Exercise actual protobuf wire encoding, not shared object aliases.
		b, err := proto.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		wire := &meshpb.NetMap{}
		if err = proto.Unmarshal(b, wire); err != nil {
			t.Fatal(err)
		}
		got, grant, err := d.Apply(wire)
		if err != nil {
			t.Fatal(err)
		}
		got = proto.Clone(got).(*meshpb.NetMap)
		got.Sequence = 0
		if grant != wantGrant || !proto.Equal(got, m) {
			t.Fatalf("decoded map differs: %v", got)
		}
		e = next
	}
	check(false, false)
	m = proto.Clone(m).(*meshpb.NetMap)
	m.Peers = append(m.Peers, &meshpb.Peer{NodeId: 102, NodeKey: "new-device", AllowedIps: []string{"100.64.1.0/24"}})
	check(true, false)
	m = proto.Clone(m).(*meshpb.NetMap)
	m.DerpMap = &meshpb.DERPMap{Regions: []*meshpb.DERPRegion{{Code: "new-region"}}}
	m.RelayBandwidthKbps = 123
	check(true, false)
	m = proto.Clone(m).(*meshpb.NetMap)
	m.Peers[3].Endpoints = nil
	check(true, false)
	m = proto.Clone(m).(*meshpb.NetMap)
	m.Peers = m.Peers[1:]
	check(true, false)
	m = proto.Clone(m).(*meshpb.NetMap)
	m.PacketFilter = nil
	m.RelayBandwidthKbps = 0
	m.SelfServices = nil
	check(true, false)
	m.RelayGrant = nil
	check(true, true)
	m.RelayGrant = []byte("renewed")
	check(true, true)
	// A global ACL withdrawal is often smaller as a full replacement; empty
	// peers and rules must clear the complete previous authorization.
	m.Peers = nil
	check(false, false)
	if len(d.current.Peers) != 0 || len(d.current.PacketFilter) != 0 {
		t.Fatal("revoked permissions retained")
	}
}

func TestNetMapStreamRejectsInvalidFramesWithoutAdvancing(t *testing.T) {
	full := streamMap(3)
	full.Sequence = 1
	cases := map[string]*meshpb.NetMap{
		"missing base":           {Delta: true, Sequence: 2},
		"gap":                    {Delta: true, Sequence: 3, BaseSequence: 1},
		"replay":                 {Delta: true, Sequence: 1, BaseSequence: 1},
		"hidden metadata":        {Delta: true, Sequence: 2, BaseSequence: 1, FilterEnabled: true},
		"grant with peers":       {Delta: true, Sequence: 2, BaseSequence: 1, GrantOnly: true, Peers: full.Peers},
		"unknown delete":         {Delta: true, Sequence: 2, BaseSequence: 1, RemovedPeerIds: []int64{999}},
		"duplicate upsert":       {Delta: true, Sequence: 2, BaseSequence: 1, Peers: []*meshpb.Peer{full.Peers[0], full.Peers[0]}},
		"delete upsert conflict": {Delta: true, Sequence: 2, BaseSequence: 1, RemovedPeerIds: []int64{2}, Peers: full.Peers[:1]},
		"identity change":        {Delta: true, Sequence: 2, BaseSequence: 1, MetadataPresent: true, Self: &meshpb.Peer{NodeId: 9}},
		"legacy downgrade":       streamMap(3),
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			var d NetMapDecoder
			if _, _, err := d.Apply(full); err != nil {
				t.Fatal(err)
			}
			if _, _, err := d.Apply(f); err == nil {
				t.Fatal("accepted invalid frame")
			}
			if d.seq != 1 || len(d.current.Peers) != 3 {
				t.Fatal("invalid frame changed baseline")
			}
			if _, _, err := d.Apply(&meshpb.NetMap{Delta: true, BaseSequence: 1, Sequence: 2, GrantOnly: true}); err != nil {
				t.Fatal(err)
			}
		})
	}
	var fresh NetMapDecoder
	if _, _, err := fresh.Apply(&meshpb.NetMap{Delta: true, BaseSequence: 1, Sequence: 2}); err == nil {
		t.Fatal("delta without initial full accepted")
	}
	// Reconnecting has no dependency on any old stream's sequence or history.
	if _, _, err := fresh.Apply(full); err != nil {
		t.Fatal(err)
	}
}

func TestNetMapEncoderTransactionalAndBounded(t *testing.T) {
	var e NetMapEncoder
	m := streamMap(100)
	_, next, err := e.Next(m)
	if err != nil {
		t.Fatal(err)
	}
	// Discarding an unsent frame leaves the original stream at sequence zero.
	f, _, err := e.Next(m)
	if err != nil || f.Sequence != 1 || f.Delta {
		t.Fatal("unsent frame advanced baseline")
	}
	e = next
	var d NetMapDecoder
	if _, _, err = d.Apply(proto.Clone(f).(*meshpb.NetMap)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		m.Peers[0].Name = fmt.Sprint(i)
		f, next, err = e.Next(m)
		if err != nil {
			t.Fatal(err)
		}
		e = next
		if _, _, err = d.Apply(proto.Clone(f).(*meshpb.NetMap)); err != nil || len(d.current.Peers) != 100 {
			t.Fatal("decoder retained historical graphs", err)
		}
		if len(e.peers) != 100 {
			t.Fatal("retained historical peers")
		}
	}
	m.Peers = nil
	f, e, err = e.Next(m)
	if err != nil || len(e.peers) != 0 {
		t.Fatal("deleted peers retained")
	}
	if _, _, err = d.Apply(f); err != nil || len(d.current.Peers) != 0 {
		t.Fatal("decoder retained deleted peers", err)
	}
	m = streamMap(2)
	m.Peers[0].Name = string([]byte{255})
	if _, _, err = e.Next(m); err == nil {
		t.Fatal("invalid protobuf string accepted")
	}
}
