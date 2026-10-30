package rpc

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	"github.com/calabinet/calabi/apps/calabi-coord/internal/platform/identity"
	"github.com/calabinet/calabi/apps/calabi-coord/internal/platform/store"
	pb "github.com/calabinet/calabi/pkg/hooks-proto/hookspb"
	"google.golang.org/grpc"
)

func fleetInt(name string, fallback, min, max int) int {
	n, err := strconv.Atoi(os.Getenv(name))
	if err != nil || n < min || n > max {
		return fallback
	}
	return n
}

// URL query parameters must not override the validated host/database or inject
// startup options that bypass the disposable schema configuration.
func fleetLoopbackDatabaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "postgres" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") || u.Path != "/calabi_mesh_bench" {
		return nil, fmt.Errorf("fleet PostgreSQL requires disposable loopback database")
	}
	for key := range u.Query() {
		switch strings.ToLower(key) {
		case "host", "hostaddr", "dbname", "port", "service", "servicefile", "options":
			return nil, fmt.Errorf("fleet PostgreSQL rejects connection overrides")
		}
	}
	return u, nil
}

// Only an explicitly named local disposable database can be used. Each run
// owns a generated schema; no existing tables are migrated or truncated.
func fleetDatabase(t testing.TB, ctx context.Context) (*sql.DB, string) {
	return fleetDatabaseNamed(t, ctx, "fleet-coord")
}

func fleetDatabaseNamed(t testing.TB, ctx context.Context, application string) (*sql.DB, string) {
	t.Helper()
	dsn := os.Getenv("CALABI_FLEET_PG_DSN")
	if dsn == "" {
		db, err := sql.Open("sqlite", fmt.Sprintf("file:process-%d?mode=memory&cache=shared&_pragma=foreign_keys(1)", os.Getpid()))
		if err != nil {
			t.Fatal(err)
		}
		db.SetMaxOpenConns(1)
		return db, dialect.SQLite
	}
	u, err := fleetLoopbackDatabaseURL(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal("open fixture PostgreSQL")
	}
	schema := fmt.Sprintf("fleet_%d_%d", os.Getpid(), time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		admin.Close()
		t.Fatalf("create fixture schema: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.ExecContext(cleanupCtx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("cleanup schema: %v", err)
		}
		admin.Close()
	})
	q := u.Query()
	q.Set("search_path", schema)
	q.Set("application_name", application)
	u.RawQuery = q.Encode()
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal("open isolated PostgreSQL")
	}
	pool := fleetInt("CALABI_FLEET_PG_POOL", 8, 1, 64)
	db.SetMaxOpenConns(pool)
	db.SetMaxIdleConns(fleetInt("CALABI_FLEET_PG_IDLE", pool, 0, pool))
	return db, dialect.Postgres
}

type fleetServices struct {
	*store.Store
	reads atomic.Int64
	rows  atomic.Int64
}

func (s *fleetServices) ListServices(ctx context.Context, org core.MeshnetID) ([]core.Service, error) {
	r, err := s.Store.ListServices(ctx, org)
	s.reads.Add(1)
	s.rows.Add(int64(len(r)))
	return r, err
}
func (s *fleetServices) ListNodeServices(ctx context.Context, org core.MeshnetID, id int64) ([]core.Service, error) {
	if p, ok := any(s.Store).(interface {
		ListNodeServices(context.Context, core.MeshnetID, int64) ([]core.Service, error)
	}); ok {
		r, err := p.ListNodeServices(ctx, org, id)
		s.reads.Add(1)
		s.rows.Add(int64(len(r)))
		return r, err
	}
	all, err := s.ListServices(ctx, org)
	var r []core.Service
	for _, v := range all {
		if v.NodeID == id {
			r = append(r, v)
		}
	}
	return r, err
}

// Exercise the production identity adapter with injected RPC dependency delay.
// This is not a real identity-svc deployment or an authentication cache.
type fleetIdentityRPC struct {
	groups  int
	delay   time.Duration
	active  atomic.Bool
	mu      sync.Mutex
	calls   int
	buckets map[int64]int
}

func (f *fleetIdentityRPC) wait(ctx context.Context) error {
	if !f.active.Load() {
		return nil
	}
	f.mu.Lock()
	f.calls++
	f.buckets[time.Now().UnixMilli()/100]++
	f.mu.Unlock()
	timer := time.NewTimer(f.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func (f *fleetIdentityRPC) ValidateToken(ctx context.Context, r *pb.ValidateTokenRequest, _ ...grpc.CallOption) (*pb.ValidateTokenResponse, error) {
	if err := f.wait(ctx); err != nil {
		return nil, err
	}
	g, err := strconv.Atoi(strings.TrimPrefix(r.AccessToken, "fleet-org-"))
	valid := err == nil && r.AccessToken == fmt.Sprintf("fleet-org-%d", g) && g >= 1 && g <= f.groups
	return &pb.ValidateTokenResponse{Valid: valid, UserId: int64(g), Roles: []string{fmt.Sprintf("org:%d ws:1 scopes:org.role.developer", g)}}, nil
}
func (f *fleetIdentityRPC) CheckEnrollment(ctx context.Context, r *pb.CheckEnrollmentRequest, _ ...grpc.CallOption) (*pb.CheckEnrollmentResponse, error) {
	if err := f.wait(ctx); err != nil {
		return nil, err
	}
	return &pb.CheckEnrollmentResponse{Valid: r.OrgId >= 1 && r.OrgId <= int64(f.groups) && r.UserId == r.OrgId}, nil
}
func (f *fleetIdentityRPC) authenticator(logger *slog.Logger) core.Authenticator {
	return identity.Wrap(logger, f)
}
func (f *fleetIdentityRPC) reset() {
	f.mu.Lock()
	f.calls = 0
	f.buckets = map[int64]int{}
	f.mu.Unlock()
	f.active.Store(true)
}
func (f *fleetIdentityRPC) metrics() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	peak := 0
	for _, n := range f.buckets {
		if n > peak {
			peak = n
		}
	}
	return f.calls, peak
}
