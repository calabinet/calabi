package rpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/adminhttp"
	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestSecurityChangeInterruptsSlowSendsAndReleasesBudget(t *testing.T) {
	s, st, nodes, e := sharedMapFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 2)
	var streams []*cancelledMapStream
	for i := 0; i < 2; i++ {
		stream := &cancelledMapStream{snapshotStream: &snapshotStream{ctx: ctx}, entered: make(chan struct{}), exited: make(chan struct{})}
		streams = append(streams, stream)
		go func() { done <- s.sendNetMap(stream, nodes[0], e, false) }()
		select {
		case <-stream.entered:
		case <-time.After(time.Second):
			t.Fatal("Send did not start")
		}
	}
	if err := st.SetDisabled(ctx, nodes[1].ID, true); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	s.notif.Bump(1)
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if status.Code(err) != codes.Aborted {
				t.Fatalf("must end superseded RPC, got %v", err)
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatal("slow send held shared budget after version invalidation")
		}
	}
	healthyCtx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	healthy := &snapshotStream{ctx: healthyCtx}
	if err := s.sendNetMap(healthy, nodes[2], e, false); err != nil {
		t.Fatal(err)
	}
	if len(healthy.sent.Peers) != 1 || healthy.sent.Peers[0].NodeId == nodes[1].ID {
		t.Fatal("revoked device retained")
	}
	if s.coord.Performance.BuildActive.Load() != 0 {
		t.Fatal("slot leak")
	}
	t.Logf("healthy revocation delivered after %s", time.Since(started))
	// In gRPC returning ends the RPC and cancels Send. The direct test harness
	// supplies that transport cancellation here; it must not launch another Send.
	cancel()
	for _, stream := range streams {
		select {
		case <-stream.exited:
		case <-time.After(time.Second):
			t.Fatal("Send worker leaked")
		}
	}
}

func TestLegacyRollbackCancelsStalledSendOnSessionEnd(t *testing.T) {
	s, _, nodes, e := sharedMapFixture(t)
	s.legacyMaps = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &cancelledMapStream{snapshotStream: &snapshotStream{ctx: ctx}, entered: make(chan struct{}), exited: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- s.sendNetMap(stream, nodes[0], e, false) }()
	select {
	case <-stream.entered:
	case <-time.After(time.Second):
		t.Fatal("legacy Send did not enter")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled legacy send succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("legacy subscription retained admission on session end")
	}
	select {
	case <-stream.exited:
	case <-time.After(time.Second):
		t.Fatal("legacy Send worker leaked")
	}
}

type failingAliasWrites struct{ core.NodeStore }

func (failingAliasWrites) UpdateRouteAliases(context.Context, int64, []core.RouteAlias) error {
	return errors.New("injected alias persistence failure")
}

func TestPartialRouteWithdrawalInvalidatesSnapshotThroughAdminHTTP(t *testing.T) {
	s, st, nodes, e := sharedMapFixture(t)
	ctx := context.Background()
	n, err := st.Get(ctx, nodes[1].ID)
	if err != nil {
		t.Fatal(err)
	}
	prefix := netip.MustParsePrefix("192.168.99.0/24")
	n.AdvertisedRoutes = []netip.Prefix{prefix}
	n.ApprovedRoutes = []netip.Prefix{prefix}
	n.AliasedRoutes = []netip.Prefix{prefix}
	n.RouteAliases = []core.RouteAlias{{Real: prefix, Alias: netip.MustParsePrefix("100.96.99.0/24")}}
	if _, err = st.Upsert(ctx, n); err != nil {
		t.Fatal(err)
	}
	s.coord.Nodes = failingAliasWrites{NodeStore: st}
	initial := &snapshotStream{ctx: ctx}
	if err = s.sendNetMap(initial, nodes[0], e, false); err != nil {
		t.Fatal(err)
	}
	if !hasRoute(initial.sent, "100.96.99.0/24") {
		t.Fatal("fixture did not advertise initial alias")
	}
	v, changed := s.notif.Version(1)
	h := adminhttp.New(s.coord, s.notif, slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, fmt.Sprintf("/admin/meshnets/1/nodes/%d/routes", n.ID), strings.NewReader(`{"approved":[]}`)))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("partial write should report error: %d %s", w.Code, w.Body)
	}
	if !mapChanged(changed) {
		t.Fatal("failed write left old generation valid")
	}
	if next, _ := s.notif.Version(1); next == v {
		t.Fatal("cache not invalidated")
	}
	row, err := st.Get(ctx, n.ID)
	if err != nil || len(row.ApprovedRoutes) != 0 {
		t.Fatal("fixture did not commit first write", err)
	}
	updated := &snapshotStream{ctx: ctx}
	if err = s.sendNetMap(updated, nodes[0], e, false); err != nil {
		t.Fatal(err)
	}
	if hasRoute(updated.sent, "100.96.99.0/24") {
		t.Fatal("withdrawn route re-published from stale cache")
	}
	owner := &snapshotStream{ctx: ctx}
	if err = s.sendNetMap(owner, nodes[1], e, false); err != nil {
		t.Fatal(err)
	}
	if len(owner.sent.SubnetAliases) != 0 {
		t.Fatal("router was told to retain an orphaned alias rewrite")
	}
	// The legacy/full rollback path must enforce the same publication boundary.
	legacy, err := s.coord.NetMapFor(ctx, nodes[1].ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(toProtoNetMap(legacy).SubnetAliases) != 0 {
		t.Fatal("rollback republished withdrawn alias")
	}
}

func hasRoute(m *meshpb.NetMap, route string) bool {
	for _, p := range m.Peers {
		for _, ip := range p.AllowedIps {
			if ip == route {
				return true
			}
		}
	}
	return false
}

type failedNodeDeletion struct{ core.NodeStore }

func (failedNodeDeletion) Delete(context.Context, int64) error {
	return errors.New("injected delete failure")
}

type failedServiceCreation struct{ core.ServiceStore }

func (failedServiceCreation) CreateService(context.Context, core.Service) (*core.Service, error) {
	return nil, errors.New("injected service create failure")
}

type failedRecordPurge struct{ core.ConnRecordStore }

func (failedRecordPurge) PurgeConnRecordsOf(context.Context, core.MeshnetID) (int, error) {
	return 0, errors.New("injected record purge failure")
}

func TestPartialServiceAndSettingsWritesInvalidateSnapshot(t *testing.T) {
	for _, op := range []string{"delete", "declarations", "settings"} {
		t.Run(op, func(t *testing.T) {
			s, st, nodes, e := sharedMapFixture(t)
			ctx := context.Background()
			services := core.NewMemServiceStore()
			if _, err := services.CreateService(ctx, core.Service{Meshnet: 1, NodeID: nodes[1].ID, Name: "web", Proto: "tcp", Port: 443, Approved: true, Source: core.ServiceSourceNode}); err != nil {
				t.Fatal(err)
			}
			s.coord.Services = services
			acl := core.NewMemACLStore()
			doc := core.ACLPolicy{ACLs: []core.ACLRule{{Action: "accept", Src: []string{"*"}, Dst: []string{"*"}, Ports: []string{"svc:web"}}}}
			if err := acl.SetACL(ctx, 1, doc); err != nil {
				t.Fatal(err)
			}
			s.coord.ACL = acl
			s.coord.Policy = core.ACLFilter{Store: acl, Fallback: core.AllowAllPolicy{}}
			if op == "settings" {
				s.coord.Settings = core.NewMemSettingsStore()
				s.coord.ConnRecords = failedRecordPurge{}
			}
			initial := &snapshotStream{ctx: ctx}
			if err := s.sendNetMap(initial, nodes[1], e, false); err != nil {
				t.Fatal(err)
			}
			if len(initial.sent.PacketFilter) == 0 {
				t.Fatal("fixture did not allow service")
			}
			_, changed := s.notif.Version(1)
			h := adminhttp.New(s.coord, s.notif, slog.New(slog.NewTextHandler(io.Discard, nil)))
			w := httptest.NewRecorder()
			switch op {
			case "delete":
				s.coord.Nodes = failedNodeDeletion{NodeStore: st}
				h = adminhttp.New(s.coord, s.notif, slog.New(slog.NewTextHandler(io.Discard, nil)))
				h.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/admin/meshnets/1/nodes/%d", nodes[1].ID), nil))
				if w.Code != 500 {
					t.Fatalf("delete status %d", w.Code)
				}
			case "declarations":
				s.coord.Services = failedServiceCreation{ServiceStore: services}
				token, err := s.sessions.start(nodes[1])
				if err != nil {
					t.Fatal(err)
				}
				_, err = s.UpdateNodeDeclarations(ctx, &meshpb.UpdateNodeDeclarationsRequest{SessionToken: token, DeclaredServices: []*meshpb.DeclaredService{{Name: "db", Proto: "tcp", Port: 5432}}})
				if status.Code(err) != codes.Internal {
					t.Fatalf("declaration error %v", err)
				}
			case "settings":
				h.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/admin/meshnets/1/settings", strings.NewReader(`{"alias_addr_budget":512,"conn_records_disabled":true}`)))
				if w.Code != 500 {
					t.Fatalf("settings status %d", w.Code)
				}
			}
			if !mapChanged(changed) {
				t.Fatal("partial mutation did not invalidate shared generation")
			}
			updated := &snapshotStream{ctx: ctx}
			if err := s.sendNetMap(updated, nodes[1], e, false); err != nil {
				t.Fatal(err)
			}
			if op == "settings" {
				if updated.sent.AliasBudgetAddrs != 512 {
					t.Fatal("committed setting hidden by cached snapshot")
				}
			} else if len(updated.sent.PacketFilter) != 0 {
				t.Fatal("removed service still grants ports")
			}
		})
	}
}

func TestReplacementSessionCancelsOldSubscriptionsAndFreesAdmission(t *testing.T) {
	c := startTestServer(t)
	n := enroll(t, c, devKey, "owner")
	enroll(t, c, devKey, "peer")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var old []meshpb.Coordinator_PullNetMapClient
	for i := 0; i < 2; i++ {
		stream, err := c.PullNetMap(ctx, &meshpb.PullNetMapRequest{NodeId: n.id, SessionToken: n.token, DeltaNetmap: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = stream.Recv(); err != nil {
			t.Fatal(err)
		}
		old = append(old, stream)
	}
	resp, err := enrollAs(ctx, c, devKey, "owner", n.key, n.priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, stream := range old {
		// A frame already queued before replacement can still arrive. The stream
		// itself must end, not keep its lease or renew under the revoked token.
		for {
			_, err = stream.Recv()
			if err != nil {
				break
			}
		}
		if status.Code(err) != codes.Canceled {
			t.Fatalf("old session stream did not cancel: %v", err)
		}
	}
	stream, err := c.PullNetMap(ctx, &meshpb.PullNetMapRequest{NodeId: resp.NodeId, SessionToken: resp.SessionToken, DeltaNetmap: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = stream.Recv(); err != nil {
		t.Fatal("replacement session blocked by stale admissions", err)
	}
}

func TestNetMapAdmissionBoundsAndCleanup(t *testing.T) {
	a := newNetMapAdmissions()
	a.perGroup = 3
	a.global = 4
	a1, err := a.acquire(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := a.acquire(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.acquire(1, 1); status.Code(err) != codes.ResourceExhausted {
		t.Fatal("device bound missing", err)
	}
	b, err := a.acquire(1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.acquire(1, 3); status.Code(err) != codes.ResourceExhausted {
		t.Fatal("group bound missing", err)
	}
	c, err := a.acquire(2, 4)
	if err != nil {
		t.Fatal("one group blocked another", err)
	}
	if _, err = a.acquire(3, 5); status.Code(err) != codes.ResourceExhausted {
		t.Fatal("global bound missing", err)
	}
	a1()
	a1()
	a2()
	b()
	c()
	if a.total != 0 || len(a.nodes) != 0 || len(a.groups) != 0 || len(a.leases) != 0 {
		t.Fatal("admission state retained")
	}
	// Concurrent use cannot over-admit and every rejection leaves no state.
	var wg sync.WaitGroup
	releaseGate := make(chan struct{})
	outcomes := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := a.acquire(1, 1)
			outcomes <- err
			if err == nil {
				<-releaseGate
				release()
			}
		}()
	}
	accepted := 0
	for i := 0; i < 32; i++ {
		if err := <-outcomes; err == nil {
			accepted++
		} else if status.Code(err) != codes.ResourceExhausted {
			t.Error(err)
		}
	}
	close(releaseGate)
	wg.Wait()
	if accepted != 2 {
		t.Fatalf("concurrent admission accepted %d streams, want 2", accepted)
	}
	if a.total != 0 || len(a.nodes) != 0 || len(a.groups) != 0 || len(a.leases) != 0 {
		t.Fatal("concurrent admission leaked state")
	}
}

func TestNetMapAdmissionAllowsReconnectAndRejectsDuplicateStreams(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint(legacy), func(t *testing.T) {
			t.Setenv("CALABI_COORD_LEGACY_NETMAP", "")
			if legacy {
				t.Setenv("CALABI_COORD_LEGACY_NETMAP", "1")
			}
			c := startTestServer(t)
			n := enroll(t, c, devKey, "owner")
			enroll(t, c, devKey, "peer")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			firstCtx, closeFirst := context.WithCancel(ctx)
			defer closeFirst()
			open := func(ctx context.Context) (meshpb.Coordinator_PullNetMapClient, error) {
				stream, err := c.PullNetMap(ctx, &meshpb.PullNetMapRequest{NodeId: n.id, SessionToken: n.token, DeltaNetmap: true})
				if err != nil {
					return nil, err
				}
				_, err = stream.Recv()
				return stream, err
			}
			if _, err := open(firstCtx); err != nil {
				t.Fatal(err)
			}
			second, err := open(ctx)
			if err != nil {
				t.Fatal("reconnect overlap rejected", err)
			}
			if _, err = open(ctx); status.Code(err) != codes.ResourceExhausted {
				t.Fatalf("third duplicate stream admitted: %v", err)
			}
			closeFirst()
			deadline := time.Now().Add(time.Second)
			for {
				_, err = open(ctx)
				if err == nil {
					break
				}
				if status.Code(err) != codes.ResourceExhausted || time.Now().After(deadline) {
					t.Fatal("cancelled stream did not release quota", err)
				}
				time.Sleep(10 * time.Millisecond)
			}
			enroll(t, c, devKey, "another")
			if _, err = second.Recv(); err != nil {
				t.Fatal("closing old stream orphaned surviving subscription", err)
			}
		})
	}
}
