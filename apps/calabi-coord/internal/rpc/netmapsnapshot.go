package rpc

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var errMapSuperseded = errors.New("netmap generation superseded")

// Entries exist only for live subscribers. Each meshnet may occupy two of the
// eight global build/send slots, so a large meshnet cannot fill the global
// queue with thousands of jobs ahead of another meshnet.
type netMapSnapshots struct {
	mu     sync.Mutex
	groups map[core.MeshnetID]*meshMapState
	slots  chan struct{}
}
type meshMapState struct {
	mu           sync.Mutex
	refs         int // guarded by manager.mu
	version      uint64
	snapshot     *core.NetMapSnapshot
	err          error
	loaded       time.Time
	loading      *mapSnapshotLoad
	slots        chan struct{}
	wireSnapshot *core.NetMapSnapshot
	wire         *snapshotWirePeers
	nextLoad     time.Time // minimum spacing of expensive reads, not a cache TTL
}

// Changes still invalidate immediately. Coalesce obsolete pending loads during
// a burst without postponing their invalidation or sending any old snapshot.
// The deadline advances only when a load is admitted, never on notifications.
func (e *meshMapState) waitSnapshotTurn(ctx context.Context, changed <-chan struct{}) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if mapChanged(changed) {
			return errMapSuperseded
		}
		e.mu.Lock()
		wait := time.Until(e.nextLoad)
		if wait <= 0 {
			e.nextLoad = time.Now().Add(50 * time.Millisecond)
			e.mu.Unlock()
			return nil
		}
		e.mu.Unlock()
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-changed:
			timer.Stop()
			return errMapSuperseded
		case <-timer.C:
		}
	}
}

// Public wire peers are identical across recipients after core visibility has
// selected them. This cache is tied to the actual snapshot pointer, including
// forced refreshes without a notifier version change. It holds no ACL outcome.
type snapshotWirePeers struct {
	mu           sync.Mutex
	peers        map[int64]*meshpb.Peer
	fingerprints meshproto.PeerFingerprintCache
}

func (e *meshMapState) wirePeers(snap *core.NetMapSnapshot) *snapshotWirePeers {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.wireSnapshot != snap {
		e.wireSnapshot = snap
		e.wire = &snapshotWirePeers{peers: make(map[int64]*meshpb.Peer)}
	}
	return e.wire
}
func (c *snapshotWirePeers) peer(n *core.Node) *meshpb.Peer {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.peers[n.ID]
	if p == nil {
		p = toProtoPeer(n)
		c.peers[n.ID] = p
	}
	return p
}

type mapSnapshotLoad struct {
	version uint64
	done    chan struct{}
}

func newNetMapSnapshots() *netMapSnapshots {
	return &netMapSnapshots{groups: make(map[core.MeshnetID]*meshMapState), slots: make(chan struct{}, 8)}
}
func (m *netMapSnapshots) open(t core.MeshnetID) *meshMapState {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.groups[t]
	if e == nil {
		e = &meshMapState{slots: make(chan struct{}, 2)}
		m.groups[t] = e
	}
	e.refs++
	return e
}
func (m *netMapSnapshots) close(t core.MeshnetID, e *meshMapState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e.refs--
	if e.refs == 0 && m.groups[t] == e {
		delete(m.groups, t)
	}
}

func mapChanged(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func (s *Server) snapshot(ctx context.Context, t core.MeshnetID, e *meshMapState, v uint64, changed <-chan struct{}, refresh bool) (*core.NetMapSnapshot, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if mapChanged(changed) {
			return nil, errMapSuperseded
		}
		e.mu.Lock()
		// Grant refresh re-reads mutable external inputs. Only nearby refreshes
		// share that read; a notification always invalidates immediately.
		if e.version == v && (e.snapshot != nil || e.err != nil) && ((!refresh && e.err == nil) || time.Since(e.loaded) < time.Second) {
			snap, err := e.snapshot, e.err
			e.mu.Unlock()
			s.coord.Performance.SnapshotHits.Add(1)
			return snap, err
		}
		if loading := e.loading; loading != nil && loading.version == v {
			e.mu.Unlock()
			select {
			case <-loading.done:
				continue
			case <-changed:
				return nil, errMapSuperseded
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		loading := &mapSnapshotLoad{version: v, done: make(chan struct{})}
		e.loading = loading
		// Once a refresh starts, concurrent callers must join it rather than
		// silently falling back to an older successful authorization snapshot.
		e.snapshot, e.err = nil, nil
		e.mu.Unlock()
		loadCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		// Cancel SQL already in flight when a restrictive mutation supersedes it.
		go func() {
			select {
			case <-changed:
				cancel()
			case <-loadCtx.Done():
			}
		}()
		var snap *core.NetMapSnapshot
		scheduleStarted := time.Now()
		err := e.waitSnapshotTurn(loadCtx, changed)
		s.coord.Performance.Stages.Observe(core.SnapshotSchedule, scheduleStarted)
		var release func()
		if err == nil {
			release, err = s.mapSlot(loadCtx, e, changed)
		}
		if err == nil {
			readStarted := time.Now()
			snap, err = s.coord.PrepareNetMapSnapshot(loadCtx, t)
			s.coord.Performance.Stages.Observe(core.SnapshotRead, readStarted)
			release()
		}
		if err == nil {
			err = loadCtx.Err()
		}
		cancel()
		stale := mapChanged(changed)
		e.mu.Lock()
		if !stale && !errors.Is(err, context.Canceled) {
			e.snapshot, e.err, e.version, e.loaded = snap, err, v, time.Now()
		}
		if e.loading == loading {
			e.loading = nil
		}
		close(loading.done)
		e.mu.Unlock()
		if stale {
			return nil, errMapSuperseded
		}
		return snap, err
	}
}

func (s *Server) mapSlot(ctx context.Context, e *meshMapState, changed <-chan struct{}) (func(), error) {
	defer s.coord.Performance.Stages.Observe(core.MapQueue, time.Now())
	select {
	case e.slots <- struct{}{}:
	case <-changed:
		return nil, errMapSuperseded
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case s.maps.slots <- struct{}{}:
	case <-changed:
		<-e.slots
		return nil, errMapSuperseded
	case <-ctx.Done():
		<-e.slots
		return nil, ctx.Err()
	}
	p := &s.coord.Performance
	n := p.BuildActive.Add(1)
	for old := p.BuildPeak.Load(); n > old; old = p.BuildPeak.Load() {
		if p.BuildPeak.CompareAndSwap(old, n) {
			break
		}
	}
	return func() { p.BuildActive.Add(-1); <-s.maps.slots; <-e.slots }, nil
}

func (s *Server) sendNetMap(stream meshpb.Coordinator_PullNetMapServer, self *core.Node, e *meshMapState, refresh bool) error {
	if s.legacyMaps {
		return s.sendLegacyNetMap(stream, self.ID)
	}
	ctx := stream.Context()
	for {
		v, changed := s.notif.Version(self.Meshnet)
		snap, err := s.snapshot(ctx, self.Meshnet, e, v, changed, refresh)
		if errors.Is(err, errMapSuperseded) {
			s.coord.Performance.StaleMaps.Add(1)
			continue
		}
		if err != nil {
			return status.Errorf(codes.Internal, "compute shared netmap: %v", err)
		}
		release, err := s.mapSlot(ctx, e, changed)
		if errors.Is(err, errMapSuperseded) {
			s.coord.Performance.StaleMaps.Add(1)
			continue
		}
		if err != nil {
			return err
		}
		err = func() error {
			defer release()
			if mapChanged(changed) {
				return errMapSuperseded
			}
			nm, peers, err := snap.NetMapViewFor(ctx, self.ID)
			if err != nil {
				if errors.Is(err, core.ErrNodeDisabled) {
					return status.Error(codes.PermissionDenied, "node is disabled")
				}
				if errors.Is(err, core.ErrNodeNotFound) {
					return status.Error(codes.NotFound, "node not found")
				}
				return status.Errorf(codes.Internal, "compute netmap: %v", err)
			}
			if nm.Self.NodeKey != self.NodeKey || nm.Self.Meshnet != self.Meshnet {
				return status.Error(codes.Unauthenticated, "node identity changed; register again")
			}
			wire := e.wirePeers(snap)
			out := toProtoNetMapWithPeers(nm, wire.peer)
			out.Peers = make([]*meshpb.Peer, 0, len(peers))
			for _, peer := range peers {
				out.Peers = append(out.Peers, wire.peer(peer))
			}
			s.addFileTransfers(out)
			if mapChanged(changed) {
				return errMapSuperseded
			}
			if d, ok := stream.(*deltaNetMapStream); ok {
				d.fingerprints = &wire.fingerprints
			}
			return s.sendNetMapPayload(stream, out, changed)
		}()
		if errors.Is(err, errMapSuperseded) {
			s.coord.Performance.StaleMaps.Add(1)
			continue
		}
		return err
	}
}
