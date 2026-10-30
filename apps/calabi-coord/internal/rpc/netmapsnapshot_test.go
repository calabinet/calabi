package rpc

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type snapshotNodeStore struct {
	core.NodeStore
	lists     atomic.Uint64
	fail      atomic.Bool
	intercept func(context.Context, []*core.Node)
}

func (s *snapshotNodeStore) ListMeshnet(ctx context.Context, t core.MeshnetID) ([]*core.Node, error) {
	s.lists.Add(1)
	if s.fail.Load() {
		return nil, errors.New("store unavailable")
	}
	nodes, err := s.NodeStore.ListMeshnet(ctx, t)
	if s.intercept != nil {
		s.intercept(ctx, nodes)
	}
	return nodes, err
}

type snapshotStream struct {
	meshpb.Coordinator_PullNetMapServer
	ctx  context.Context
	sent *meshpb.NetMap
}

func (s *snapshotStream) Context() context.Context     { return s.ctx }
func (s *snapshotStream) Send(nm *meshpb.NetMap) error { s.sent = nm; return nil }

func sharedMapFixture(t *testing.T) (*Server, *snapshotNodeStore, []*core.Node, *meshMapState) {
	t.Helper()
	st := &snapshotNodeStore{NodeStore: core.NewMemNodeStore()}
	var nodes []*core.Node
	for i := 1; i <= 3; i++ {
		n, err := st.Upsert(context.Background(), &core.Node{Meshnet: 1, Name: "device", NodeKey: meshproto.NodeKey{byte(i)}, Approved: true})
		if err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, n)
	}
	c := &core.Coordinator{Nodes: st, Policy: core.AllowAllPolicy{}, DERP: core.StaticDERP{}}
	notif := core.NewNotifier()
	_, unsub := notif.Subscribe(1, nodes[0].ID)
	t.Cleanup(unsub)
	s := New(c, nil, notif, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.legacyMaps = false
	e := s.maps.open(1)
	t.Cleanup(func() { s.maps.close(1, e) })
	return s, st, nodes, e
}

func TestSharedNetMapCoalescesLoadsAndInvalidatesDisabledDevice(t *testing.T) {
	s, st, nodes, e := sharedMapFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	v, changed := s.notif.Version(1)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.snapshot(ctx, 1, e, v, changed, false); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if st.lists.Load() != 1 {
		t.Fatalf("concurrent loads=%d", st.lists.Load())
	}
	stream := &snapshotStream{ctx: ctx}
	if err := s.sendNetMap(stream, nodes[0], e, false); err != nil {
		t.Fatal(err)
	}
	if len(stream.sent.Peers) != 2 {
		t.Fatal("initial peers")
	}
	if err := st.SetDisabled(ctx, nodes[1].ID, true); err != nil {
		t.Fatal(err)
	}
	s.notif.Bump(1)
	if err := s.sendNetMap(stream, nodes[0], e, false); err != nil {
		t.Fatal(err)
	}
	if len(stream.sent.Peers) != 1 {
		t.Fatal("disabled peer retained in cached map")
	}
	if err := s.sendNetMap(stream, nodes[1], e, false); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("disabled caller: %v", err)
	}
	if st.lists.Load() != 2 || s.coord.Performance.NodeGets.Load() != 0 {
		t.Fatal("shared map still performs per-device reads")
	}
}

func TestSharedNetMapDiscardsSnapshotChangedDuringRead(t *testing.T) {
	s, st, nodes, e := sharedMapFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	read, finish := make(chan struct{}), make(chan struct{})
	var calls atomic.Int64
	st.intercept = func(_ context.Context, _ []*core.Node) {
		if calls.Add(1) == 1 {
			close(read)
			<-finish
		}
	}
	stream := &snapshotStream{ctx: ctx}
	done := make(chan error, 1)
	go func() { done <- s.sendNetMap(stream, nodes[0], e, false) }()
	select {
	case <-read:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := st.SetDisabled(ctx, nodes[1].ID, true); err != nil {
		t.Fatal(err)
	}
	s.notif.Bump(1)
	close(finish)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(stream.sent.Peers) != 1 || s.coord.Performance.StaleMaps.Load() == 0 {
		t.Fatal("stale allow was published")
	}
}

func TestSharedNetMapChecksVersionAgainAfterWaitingForBudget(t *testing.T) {
	s, st, nodes, e := sharedMapFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	v, changed := s.notif.Version(1)
	if _, err := s.snapshot(ctx, 1, e, v, changed, false); err != nil {
		t.Fatal(err)
	}
	a, _ := s.mapSlot(ctx, e, nil)
	b, _ := s.mapSlot(ctx, e, nil)
	stream := &snapshotStream{ctx: ctx}
	done := make(chan error, 1)
	go func() { done <- s.sendNetMap(stream, nodes[0], e, false) }()
	st.SetDisabled(ctx, nodes[1].ID, true)
	s.notif.Bump(1)
	a()
	b()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(stream.sent.Peers) != 1 {
		t.Fatal("queued stale version sent")
	}
}

func TestSharedNetMapBudgetLeavesRoomForOtherMeshnetsAndReclaimsCache(t *testing.T) {
	s, _, _, e := sharedMapFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	a, _ := s.mapSlot(ctx, e, nil)
	defer a()
	b, _ := s.mapSlot(ctx, e, nil)
	defer b()
	waitCtx, stopWaiting := context.WithCancel(ctx)
	var waiting sync.WaitGroup
	for i := 0; i < 20; i++ {
		waiting.Add(1)
		go func() {
			defer waiting.Done()
			release, err := s.mapSlot(waitCtx, e, nil)
			if err == nil {
				release()
			}
		}()
	}
	defer func() { stopWaiting(); waiting.Wait() }()
	other := s.maps.open(2)
	release, err := s.mapSlot(ctx, other, nil)
	if err != nil {
		t.Fatal("one meshnet monopolised global budget", err)
	}
	release()
	s.maps.close(2, other)
	s.maps.mu.Lock()
	_, retained := s.maps.groups[2]
	s.maps.mu.Unlock()
	if retained {
		t.Fatal("inactive meshnet retained snapshot entry")
	}
	if peak := s.coord.Performance.BuildPeak.Load(); peak > 8 {
		t.Fatalf("unbounded builds: %d", peak)
	}
}

type cancelledMapStream struct {
	*snapshotStream
	entered chan struct{}
	exited  chan struct{}
}

func (s *cancelledMapStream) Send(_ *meshpb.NetMap) error {
	close(s.entered)
	defer close(s.exited)
	<-s.ctx.Done()
	return s.ctx.Err()
}

func TestSharedNetMapCancelledSendReleasesBudget(t *testing.T) {
	s, _, nodes, e := sharedMapFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &cancelledMapStream{snapshotStream: &snapshotStream{ctx: ctx}, entered: make(chan struct{}), exited: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- s.sendNetMap(stream, nodes[0], e, false) }()
	select {
	case <-stream.entered:
	case <-time.After(time.Second):
		t.Fatal("Send did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled Send succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled receiver held budget")
	}
	select {
	case <-stream.exited:
	case <-time.After(time.Second):
		t.Fatal("Send worker did not exit")
	}
	if active := s.coord.Performance.BuildActive.Load(); active != 0 {
		t.Fatalf("leaked build/send slots: %d", active)
	}
}

func TestSharedNetMapRefreshFailureDoesNotServeOldAllow(t *testing.T) {
	s, st, _, e := sharedMapFixture(t)
	ctx := context.Background()
	v, changed := s.notif.Version(1)
	if _, err := s.snapshot(ctx, 1, e, v, changed, false); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	e.loaded = time.Now().Add(-time.Minute)
	e.mu.Unlock()
	st.fail.Store(true)
	if snap, err := s.snapshot(ctx, 1, e, v, changed, true); err == nil || snap != nil {
		t.Fatal("refresh failure reused stale authorization")
	}
	if snap, err := s.snapshot(ctx, 1, e, v, changed, false); err == nil || snap != nil {
		t.Fatal("concurrent caller reused stale authorization")
	}
}

func TestSharedNetMapNewGenerationDoesNotWaitForOldSQL(t *testing.T) {
	s, st, nodes, e := sharedMapFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	read, finish := make(chan struct{}), make(chan struct{})
	var finishOnce sync.Once
	unblock := func() { finishOnce.Do(func() { close(finish) }) }
	defer unblock()
	var calls atomic.Int64
	st.intercept = func(_ context.Context, _ []*core.Node) {
		if calls.Add(1) == 1 {
			close(read)
			<-finish
		}
	}
	oldDone := make(chan error, 1)
	go func() { oldDone <- s.sendNetMap(&snapshotStream{ctx: ctx}, nodes[0], e, false) }()
	select {
	case <-read:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := st.SetDisabled(ctx, nodes[1].ID, true); err != nil {
		t.Fatal(err)
	}
	s.notif.Bump(1)
	fresh := &snapshotStream{ctx: ctx}
	newDone := make(chan error, 1)
	go func() { newDone <- s.sendNetMap(fresh, nodes[0], e, false) }()
	select {
	case err := <-newDone:
		if err != nil {
			t.Fatal(err)
		}
		if len(fresh.sent.Peers) != 1 {
			t.Fatal("security refresh used old SQL result")
		}
	case <-ctx.Done():
		t.Fatal("new generation waited for obsolete SQL")
	}
	unblock()
	select {
	case err := <-oldDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestSharedNetMapCancelledRefreshDoesNotRestoreOldSnapshot(t *testing.T) {
	s, st, nodes, e := sharedMapFixture(t)
	v, changed := s.notif.Version(1)
	if _, err := s.snapshot(context.Background(), 1, e, v, changed, false); err != nil {
		t.Fatal(err)
	}
	st.SetDisabled(context.Background(), nodes[0].ID, true)
	e.mu.Lock()
	e.loaded = time.Now().Add(-time.Minute)
	e.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var once sync.Once
	st.intercept = func(context.Context, []*core.Node) { once.Do(cancel) }
	if _, err := s.snapshot(ctx, 1, e, v, changed, true); err == nil {
		t.Fatal("cancelled refresh succeeded")
	}
	fresh, err := s.snapshot(context.Background(), 1, e, v, changed, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.NetMapFor(context.Background(), nodes[0].ID); !errors.Is(err, core.ErrNodeDisabled) {
		t.Fatal("cancelled refresh restored an old allow", err)
	}
}
