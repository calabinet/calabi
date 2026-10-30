package rpc

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	"github.com/calabinet/calabi/apps/calabi-coord/internal/platform/store"
	"github.com/calabinet/calabi/apps/calabi-coord/internal/platform/store/ent"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
)

type countedSQL struct {
	dialect.Driver
	operations atomic.Uint64
	profile    atomic.Pointer[fleetSQLProfile]
}

type fleetMapStream struct {
	meshpb.Coordinator_PullNetMapClient
	decoder       meshproto.NetMapDecoder
	lastBytes     int
	lastGrantOnly bool
}

func (s *fleetMapStream) Recv() (*meshpb.NetMap, error) {
	f, err := s.Coordinator_PullNetMapClient.Recv()
	if err != nil {
		return nil, err
	}
	s.lastBytes, s.lastGrantOnly = proto.Size(f), f.GrantOnly
	if f.Sequence == 0 && !f.Delta {
		return f, nil
	}
	m, _, err := s.decoder.Apply(f)
	return m, err
}

func (d *countedSQL) Query(ctx context.Context, q string, args, v any) error {
	d.operations.Add(1)
	done := d.profile.Load().start(q)
	err := d.Driver.Query(ctx, q, args, v)
	done(err)
	return err
}
func (d *countedSQL) Exec(ctx context.Context, q string, args, v any) error {
	d.operations.Add(1)
	done := d.profile.Load().start(q)
	err := d.Driver.Exec(ctx, q, args, v)
	done(err)
	return err
}
func (d *countedSQL) Tx(ctx context.Context) (dialect.Tx, error) {
	profile := d.profile.Load()
	done := profile.start("BEGIN")
	tx, err := d.Driver.Tx(ctx)
	done(err)
	if err != nil {
		return nil, err
	}
	return &countedTx{Tx: tx, calls: &d.operations, profile: profile}, nil
}

type countedTx struct {
	dialect.Tx
	calls   *atomic.Uint64
	profile *fleetSQLProfile
}

func (d *countedTx) Query(ctx context.Context, q string, args, v any) error {
	d.calls.Add(1)
	done := d.profile.start(q)
	err := d.Tx.Query(ctx, q, args, v)
	done(err)
	return err
}
func (d *countedTx) Exec(ctx context.Context, q string, args, v any) error {
	d.calls.Add(1)
	done := d.profile.start(q)
	err := d.Tx.Exec(ctx, q, args, v)
	done(err)
	return err
}

func (d *countedTx) Commit() error {
	done := d.profile.start("COMMIT")
	err := d.Tx.Commit()
	done(err)
	return err
}
func (d *countedTx) Rollback() error {
	done := d.profile.start("ROLLBACK")
	err := d.Tx.Rollback()
	done(err)
	return err
}

// Real registration proofs, independent node sessions, persistent gRPC streams,
// protobuf encoding and the actual SQLite/ent adapter. All services are local.
// One HTTP/2 connection carries independent devices; this is a control-plane
// baseline, not a thousand full WireGuard clients or production PostgreSQL.
func TestCoordinatorFleetBaseline(t *testing.T) {
	raw := os.Getenv("CALABI_TEST_COORD_FLEET")
	if raw == "" || testing.Short() {
		t.Skip("set CALABI_TEST_COORD_FLEET=100, 300 or 1000")
	}
	n, err := strconv.Atoi(raw)
	if err != nil || (n != 100 && n != 300 && n != 1000) {
		t.Fatal("invalid fleet size")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	db, err := sql.Open("sqlite", fmt.Sprintf("file:coord-perf-%d-%d?mode=memory&cache=shared&_pragma=foreign_keys(1)", os.Getpid(), n))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	driver := &countedSQL{Driver: entsql.OpenDB(dialect.SQLite, db)}
	st := store.New(ent.NewClient(ent.Driver(driver)))
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	acl := core.NewMemACLStore()
	c := &core.Coordinator{Nodes: st, ACL: acl, Policy: core.ACLFilter{Store: acl, Fallback: core.AllowAllPolicy{}}, IPAM: core.NewMemIPAM(), DERP: core.StaticDERP{Map: core.DERPMap{Regions: []core.DERPRegion{{Code: "test"}}}}}
	deltaMode := os.Getenv("CALABI_TEST_COORD_DELTA") == "1"
	// comparisons include real per-device signed relay authorization.
	var grantClock atomic.Int64
	grantClock.Store(time.Now().Unix())
	_, grantKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("CALABI_TEST_COORD_P4_COMPARE") == "1" {
		c.RelayGrants = &core.SigningRelayGrantIssuer{Key: grantKey, Now: func() time.Time { return time.Unix(grantClock.Load(), 0) }}
	}
	notif := core.NewNotifier()
	s := New(c, core.StaticAuth{Keys: map[string]core.Identity{devKey: {Meshnet: 1}}}, notif, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if os.Getenv("CALABI_TEST_COORD_LEGACY") == "1" {
		s.legacyMaps = true
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	server := grpc.NewServer(grpc.MaxConcurrentStreams(2000))
	defer server.Stop()
	meshpb.RegisterCoordinatorServer(server, s)
	go server.Serve(ln)
	conn, err := grpc.NewClient(ln.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := meshpb.NewCoordinatorClient(conn)
	started := time.Now()
	cpuStart, _ := performanceProcessUsage()
	nodes := make([]testNode, n)
	for i := range nodes {
		nodes[i] = enroll(t, client, devKey, fmt.Sprintf("fleet-%d", i))
	}
	registrationTime := time.Since(started)
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)
	queries := driver.operations.Load()
	streams := make([]meshpb.Coordinator_PullNetMapClient, n)
	initialStart := time.Now()
	for i, node := range nodes {
		rawStream, err := client.PullNetMap(ctx, &meshpb.PullNetMapRequest{NodeId: node.id, SessionToken: node.token, DeltaNetmap: deltaMode})
		if err != nil {
			t.Fatal(err)
		}
		stream := &fleetMapStream{Coordinator_PullNetMapClient: rawStream}
		nm, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if len(nm.Peers) != n-1 {
			t.Fatalf("initial peers=%d want=%d", len(nm.Peers), n-1)
		}
		streams[i] = stream
	}
	initialTime := time.Since(initialStart)
	awaitSent := func(want uint64) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for c.Performance.Snapshot().SentMaps < want && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if c.Performance.Snapshot().SentMaps != want {
			t.Fatalf("send accounting did not reach %d", want)
		}
	}
	awaitSent(uint64(n))
	initialQueries := driver.operations.Load() - queries
	before := c.Performance.Snapshot()
	queries = driver.operations.Load()
	broadcastCPUStart, _ := performanceProcessUsage()
	// A real one-device endpoint update, identical in full and delta modes.
	if err := st.UpdateEndpoints(ctx, nodes[0].id, []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")}); err != nil {
		t.Fatal(err)
	}
	queries = driver.operations.Load()
	changeStart := time.Now()
	notif.Bump(1)
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for _, stream := range streams {
		wg.Add(1)
		go func(stream meshpb.Coordinator_PullNetMapClient) {
			defer wg.Done()
			nm, err := stream.Recv()
			if err == nil && len(nm.Peers) != n-1 {
				err = fmt.Errorf("wrong changed peer count")
			}
			if err != nil {
				errs <- err
			}
		}(stream)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	changeTime := time.Since(changeStart)
	awaitSent(before.SentMaps + uint64(n))
	after := c.Performance.Snapshot()
	if !s.legacyMaps {
		if sql := driver.operations.Load() - queries; sql != 1 {
			t.Fatalf("broadcast still performs repeated SQL: %d", sql)
		}
		if after.SnapshotLoads-before.SnapshotLoads != 1 || after.NodeGets-before.NodeGets != 0 {
			t.Fatal("snapshot not shared across the broadcast")
		}
	}
	if after.SentMaps-before.SentMaps != uint64(n) || after.Streams != int64(n) {
		t.Fatalf("wrong map/stream counters: %+v", after)
	}
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)
	cpuEnd, rss := performanceProcessUsage()
	t.Logf("devices=%d independent_sessions=%d registration=%s initial=%s initial_sql=%d broadcast=%s broadcast_sql=%d protobuf_bytes=%d build_micros=%d send_micros=%d heap_before=%d heap_after=%d cpu_seconds=%.3f peak_rss=%d", n, n, registrationTime.Round(time.Millisecond), initialTime.Round(time.Millisecond), initialQueries, changeTime.Round(time.Millisecond), driver.operations.Load()-queries, after.SentProtobufBytes-before.SentProtobufBytes, after.BuildMicros-before.BuildMicros, after.SendMicros-before.SendMicros, memBefore.HeapAlloc, memAfter.HeapAlloc, cpuEnd-cpuStart, rss)
	t.Logf("legacy=%v broadcast_cpu_seconds=%.3f shared_loads=%d shared_hits=%d build_peak=%d", s.legacyMaps, cpuEnd-broadcastCPUStart, after.SnapshotLoads-before.SnapshotLoads, after.SnapshotHits-before.SnapshotHits, after.BuildPeak)
	if deltaMode && !s.legacyMaps && after.SentProtobufBytes-before.SentProtobufBytes > uint64(n*1000) {
		t.Fatal("single-peer delta unexpectedly large")
	}
	// Advance the signing clock then deliver the same authoritative state through
	// the RPC broadcast path. The timer uses the same send path with refresh=true,
	// whose forced reread and disabled-device denial are covered separately.
	grantClock.Add(15 * 60)
	grantBefore := c.Performance.Snapshot()
	grantStart := time.Now()
	notif.Bump(1)
	grantErrors := make(chan error, n)
	for i, stream := range streams {
		wg.Add(1)
		go func(i int, stream meshpb.Coordinator_PullNetMapClient) {
			defer wg.Done()
			m, err := stream.Recv()
			if err == nil && c.RelayGrants != nil {
				g, gerr := meshproto.VerifyRelayGrant(grantKey.Public().(ed25519.PublicKey), m.RelayGrant, time.Unix(grantClock.Load(), 0))
				if gerr != nil || g.Node != nodes[i].key {
					err = fmt.Errorf("grant verification: %v", gerr)
				}
			}
			if err == nil && deltaMode && !s.legacyMaps && !stream.(*fleetMapStream).lastGrantOnly {
				err = fmt.Errorf("grant refresh carried topology")
			}
			if err != nil {
				grantErrors <- err
			}
		}(i, stream)
	}
	wg.Wait()
	close(grantErrors)
	for err := range grantErrors {
		t.Fatal(err)
	}
	awaitSent(grantBefore.SentMaps + uint64(n))
	grantAfter := c.Performance.Snapshot()
	t.Logf("delta=%v signed_grants=%v grant_round=%s grant_protobuf_bytes=%d initial_protobuf_bytes=%d", deltaMode, c.RelayGrants != nil, time.Since(grantStart).Round(time.Millisecond), grantAfter.SentProtobufBytes-grantBefore.SentProtobufBytes, before.SentProtobufBytes)
	if deltaMode && !s.legacyMaps && grantAfter.SentProtobufBytes-grantBefore.SentProtobufBytes > uint64(n*300) {
		t.Fatal("grant-only frame unexpectedly large")
	}
	// Client receipt and server counters must agree about actual encoded frames.
	var receivedBytes int
	for _, stream := range streams {
		receivedBytes += stream.(*fleetMapStream).lastBytes
	}
	if uint64(receivedBytes) != grantAfter.SentProtobufBytes-grantBefore.SentProtobufBytes {
		t.Fatal("wire byte accounting differs from client frames")
	}
	// Measure real disable propagation separately from ordinary broadcast. Each
	// subscriber must lose the device; its own stream must be terminated.
	if err := st.SetDisabled(ctx, nodes[0].id, true); err != nil {
		t.Fatal(err)
	}
	queries = driver.operations.Load()
	revokeStart := time.Now()
	notif.Bump(1)
	latencies := make(chan time.Duration, n)
	revokeErrors := make(chan error, n)
	for i, stream := range streams {
		wg.Add(1)
		go func(i int, stream meshpb.Coordinator_PullNetMapClient) {
			defer wg.Done()
			nm, err := stream.Recv()
			if i == 0 {
				if status.Code(err) != codes.PermissionDenied {
					revokeErrors <- fmt.Errorf("disabled stream: %v", err)
				}
			} else if err != nil {
				revokeErrors <- err
			} else if len(nm.Peers) != n-2 {
				revokeErrors <- fmt.Errorf("revocation peers=%d", len(nm.Peers))
			} else {
				for _, p := range nm.Peers {
					if p.NodeId == nodes[0].id {
						revokeErrors <- fmt.Errorf("disabled peer retained")
						break
					}
				}
			}
			latencies <- time.Since(revokeStart)
		}(i, stream)
	}
	wg.Wait()
	close(revokeErrors)
	close(latencies)
	for err := range revokeErrors {
		t.Fatal(err)
	}
	var samples []time.Duration
	for latency := range latencies {
		samples = append(samples, latency)
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	p95 := samples[(len(samples)*95+99)/100-1]
	t.Logf("disable_propagation_p95=%s max=%s sql=%d", p95.Round(time.Millisecond), samples[len(samples)-1].Round(time.Millisecond), driver.operations.Load()-queries)
	if !s.legacyMaps && p95 > time.Second {
		t.Fatal("controlled disable propagation P95 exceeded 1s")
	}
	// The topology snapshot and both ACL layers must advance together. A rule
	// matching no source is a valid deny-all document (not an allow-all fallback).
	if err := acl.SetACL(ctx, 1, core.ACLPolicy{ACLs: []core.ACLRule{{Action: "accept", Src: []string{"no-such-device"}, Dst: []string{"*"}, Ports: []string{"*"}}}}); err != nil {
		t.Fatal(err)
	}
	queries = driver.operations.Load()
	aclStart := time.Now()
	notif.Bump(1)
	aclTimes := make(chan time.Duration, n-1)
	aclErrors := make(chan error, n-1)
	for _, stream := range streams[1:] {
		wg.Add(1)
		go func(stream meshpb.Coordinator_PullNetMapClient) {
			defer wg.Done()
			nm, err := stream.Recv()
			if err != nil {
				aclErrors <- err
			} else if len(nm.Peers) != 0 || len(nm.PacketFilter) != 0 {
				aclErrors <- fmt.Errorf("ACL revocation retained access")
			}
			aclTimes <- time.Since(aclStart)
		}(stream)
	}
	wg.Wait()
	close(aclTimes)
	close(aclErrors)
	for err := range aclErrors {
		t.Fatal(err)
	}
	samples = nil
	for latency := range aclTimes {
		samples = append(samples, latency)
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	p95 = samples[(len(samples)*95+99)/100-1]
	t.Logf("acl_revocation_p95=%s max=%s sql=%d", p95.Round(time.Millisecond), samples[len(samples)-1].Round(time.Millisecond), driver.operations.Load()-queries)
	if !s.legacyMaps && p95 > time.Second {
		t.Fatal("controlled ACL revocation P95 exceeded 1s")
	}
	cancel()
	deadline := time.Now().Add(5 * time.Second)
	for c.Performance.Snapshot().Streams != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if c.Performance.Snapshot().Streams != 0 {
		t.Fatal("streams did not drain")
	}
}

func TestCoordinatorPerformanceCountsBuildFailure(t *testing.T) {
	c := &core.Coordinator{Nodes: core.NewMemNodeStore()}
	_, err := c.NetMapFor(context.Background(), 99)
	if err == nil {
		t.Fatal("expected unknown device")
	}
	got := c.Performance.Snapshot()
	if got.Builds != 1 || got.BuildFailures != 1 || got.NodeGets != 1 {
		t.Fatalf("bad counters: %+v", got)
	}
}

// Production-shaped SQL sources: nodes, declared services, org settings, ACL
// and private relays. Their query count must stay fixed across device maps.
func TestCoordinatorSnapshotSQLFanoutIsConstant(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", fmt.Sprintf("file:snapshot-sql-%d?mode=memory&cache=shared&_pragma=foreign_keys(1)", os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	driver := &countedSQL{Driver: entsql.OpenDB(dialect.SQLite, db)}
	st := store.New(ent.NewClient(ent.Driver(driver)))
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	var ids []int64
	for i := 1; i <= 100; i++ {
		n, err := st.Upsert(ctx, &core.Node{Meshnet: 1, Name: fmt.Sprintf("device-%d", i), NodeKey: meshproto.NodeKey{byte(i)}, Overlay: netip.AddrFrom4([4]byte{100, 64, 0, byte(i)}), Approved: true})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, n.ID)
	}
	c := &core.Coordinator{Nodes: st, Services: st, Settings: st, ACL: st, Policy: core.ACLFilter{Store: st, Fallback: core.AllowAllPolicy{}}, DERP: core.CompositeDERP{Relays: st}}
	before := driver.operations.Load()
	snap, err := c.PrepareNetMapSnapshot(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		nm, err := snap.NetMapFor(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if len(nm.Peers) != 99 {
			t.Fatal("lost authorized peers")
		}
	}
	if got := driver.operations.Load() - before; got != 5 {
		t.Fatalf("100 maps used %d SQL operations, want 5", got)
	}
}
