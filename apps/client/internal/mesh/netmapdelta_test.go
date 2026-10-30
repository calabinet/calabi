package mesh

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"google.golang.org/protobuf/proto"
)

func deltaClientFrames(t *testing.T) []*meshpb.NetMap {
	t.Helper()
	m := &meshpb.NetMap{Self: &meshpb.Peer{NodeId: 1, NodeKey: keyB64(1), OverlayAddr: "100.64.0.1"}, FilterEnabled: true, RelayGrant: []byte("old")}
	for i := 2; i <= 30; i++ {
		m.Peers = append(m.Peers, &meshpb.Peer{NodeId: int64(i), NodeKey: keyB64(byte(i)), OverlayAddr: "100.64.0.2", AllowedIps: []string{"100.64.0.2/32"}})
	}
	var e meshproto.NetMapEncoder
	var frames []*meshpb.NetMap
	push := func() {
		f, next, err := e.Next(m)
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, proto.Clone(f).(*meshpb.NetMap))
		e = next
	}
	push()
	m.RelayGrant = []byte("renewed")
	push()
	m = proto.Clone(m).(*meshpb.NetMap)
	m.Peers = m.Peers[1:]
	push()
	return frames
}

func TestCoordDeltaStreamGrantFastPathAndPeerRemoval(t *testing.T) {
	frames := deltaClientFrames(t)
	f := &fakeCoord{netmaps: frames, endWatch: true}
	c := dialFake(t, f)
	var maps []NetMap
	var grants [][]byte
	err := c.watchUpdates(context.Background(), 1, func(m NetMap) { maps = append(maps, m) }, func(g []byte) { grants = append(grants, g) })
	if !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if len(maps) != 2 || len(grants) != 1 || string(grants[0]) != "renewed" || len(maps[0].Peers) != 29 || len(maps[1].Peers) != 28 {
		t.Fatal("wrong map/grant callbacks")
	}
	for _, p := range maps[1].Peers {
		if p.NodeKey == testKey(2).Public() {
			t.Fatal("removed peer retained")
		}
	}
	// Public Watch still works for consumers without a dedicated grant method.
	maps = nil
	err = c.Watch(context.Background(), 1, func(m NetMap) { maps = append(maps, m) })
	if !errors.Is(err, io.EOF) || len(maps) != 3 || string(maps[1].RelayGrant) != "renewed" {
		t.Fatal("fallback lost authorization refresh")
	}
}

func TestCoordDeltaSequenceMismatchReconnectsForFullSnapshot(t *testing.T) {
	frames := deltaClientFrames(t)
	frames[1].BaseSequence = 999
	f := &fakeCoord{netmaps: frames, endWatch: true}
	c := dialFake(t, f)
	calls := 0
	if err := c.Watch(context.Background(), 1, func(NetMap) { calls++ }); err == nil || errors.Is(err, io.EOF) || calls != 1 {
		t.Fatalf("invalid delta was applied: %v calls=%d", err, calls)
	}
	// The controller's next Watch starts with a fresh baseline, not an old delta.
	f.mu.Lock()
	f.netmaps = deltaClientFrames(t)
	f.mu.Unlock()
	calls = 0
	if err := c.Watch(context.Background(), 1, func(NetMap) { calls++ }); !errors.Is(err, io.EOF) || calls != 3 {
		t.Fatalf("full resync failed: %v calls=%d", err, calls)
	}
}

type grantRecordingDatapath struct {
	maps   int
	grants [][]byte
}

func (d *grantRecordingDatapath) SetConfig(WGConfig) error { d.maps++; return nil }
func (d *grantRecordingDatapath) SetRelayGrant(g []byte) {
	d.grants = append(d.grants, append([]byte(nil), g...))
}
func (d *grantRecordingDatapath) Close() error { return nil }

func TestControllerDeltaGrantDoesNotReconfigurePeers(t *testing.T) {
	f := &fakeCoord{reg: &meshpb.RegisterNodeResponse{NodeId: 1, OverlayAddr: "100.64.0.1"}, netmaps: deltaClientFrames(t), endWatch: true}
	d := &grantRecordingDatapath{}
	c := &Controller{Coord: dialFake(t, f), Datapath: d, Params: RegisterParams{AuthKey: "k", NodeKey: testKey(1).Public(), NodePrivate: testKey(1)}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := c.Run(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if d.maps != 2 || len(d.grants) != 1 || string(d.grants[0]) != "renewed" {
		t.Fatalf("grant triggered graph work: maps=%d grants=%d", d.maps, len(d.grants))
	}
}
