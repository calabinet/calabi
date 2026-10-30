package rpc

// Opt-in loopback fixture for scripts/dev/mesh-process-profile.ps1. The separate
// client executable uses the real public decoder and client model conversion.
import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	entsql "entgo.io/ent/dialect/sql"
	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	"github.com/calabinet/calabi/apps/calabi-coord/internal/platform/store"
	"github.com/calabinet/calabi/apps/calabi-coord/internal/platform/store/ent"
	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestFleetProcessServer(t *testing.T) {
	path := os.Getenv("CALABI_FLEET_PROCESS")
	if path == "" || testing.Short() {
		t.Skip("opt-in separate-process fixture")
	}
	n, err := strconv.Atoi(os.Getenv("CALABI_FLEET_SIZE"))
	if err != nil || n < 2 || n > 1000 {
		t.Fatal("size must be 2..1000")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	db, dbDialect := fleetDatabase(t, ctx)
	driver := &countedSQL{Driver: entsql.OpenDB(dbDialect, db)}
	st := store.New(ent.NewClient(ent.Driver(driver)))
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	acl := core.NewMemACLStore()
	var clock atomic.Int64
	clock.Store(time.Now().Unix())
	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	c := &core.Coordinator{Nodes: st, Settings: st, ACL: acl, Policy: core.ACLFilter{Store: acl, Fallback: core.AllowAllPolicy{}}, IPAM: core.NewMemIPAM(), DERP: core.StaticDERP{}, RelayGrants: &core.SigningRelayGrantIssuer{Key: key, Now: func() time.Time { return time.Unix(clock.Load(), 0) }}}
	notif := core.NewNotifier()
	groups := fleetInt("CALABI_FLEET_GROUPS", 1, 1, 100)
	serviceCount := fleetInt("CALABI_FLEET_SERVICES", 0, 0, 8)
	if n%groups != 0 {
		t.Fatal("device count must be divisible by groups")
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	idp := &fleetIdentityRPC{groups: groups, delay: time.Duration(fleetInt("CALABI_FLEET_IDENTITY_MS", 0, 0, 2000)) * time.Millisecond}
	var authn core.Authenticator = core.StaticAuth{Keys: map[string]core.Identity{devKey: {Meshnet: 1}}}
	enhanced := groups > 1 || serviceCount > 0 || os.Getenv("CALABI_FLEET_PG_DSN") != "" || idp.delay > 0
	if enhanced {
		authn = idp.authenticator(logger)
	}
	services := &fleetServices{Store: st}
	if serviceCount > 0 {
		c.Services = services
	}
	s := New(c, authn, notif, logger)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rpcStages := &fleetRPCStats{}
	server := grpc.NewServer(grpc.MaxConcurrentStreams(2000), grpc.UnaryInterceptor(rpcStages.unary), grpc.StreamInterceptor(rpcStages.stream))
	defer server.Stop()
	meshpb.RegisterCoordinatorServer(server, s)
	go server.Serve(ln)
	conn, err := grpc.NewClient(ln.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := meshpb.NewCoordinatorClient(conn)
	type device struct {
		ID         int64
		Token, Key string
		Private    []byte
		Group      int
		AuthKey    string
	}
	devices := make([]device, n)
	for i := range devices {
		group := i % groups
		authKey := devKey
		if enhanced {
			authKey = fmt.Sprintf("fleet-org-%d", group+1)
		}
		node := enroll(t, client, authKey, fmt.Sprintf("process-%d", i))
		devices[i] = device{node.id, node.token, node.key.String(), append([]byte(nil), node.priv[:]...), group, authKey}
		for j := 0; j < serviceCount; j++ {
			if _, err := st.CreateService(ctx, core.Service{Meshnet: core.MeshnetID(group + 1), NodeID: node.id, Name: fmt.Sprintf("svc-%d", j), Proto: "tcp", Port: 8000 + j, Approved: true}); err != nil {
				t.Fatal(err)
			}
		}
	}
	secret := make([]byte, 24)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	auth := hex.EncodeToString(secret)
	control, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := flushFleetBackendStats(ctx, []*sql.DB{db}); err != nil {
		t.Fatal("initial statistics flush failed")
	}
	background := startFleetBackground(t, ctx)
	defer background.stop()
	var backgroundBaseline map[string]any
	if background != nil {
		if background.independent != nil {
			background.reset()
		} else {
			time.Sleep(10 * time.Second)
		}
		backgroundBaseline = background.snapshot()
		if backgroundBaseline["error"] != nil {
			t.Fatal("background baseline failed: ", backgroundBaseline["error"])
		}
	}
	var phaseTrace *fleetProcessTrace
	defer func() {
		if phaseTrace != nil {
			phaseTrace.stop()
		}
	}()
	var phase runtime.MemStats
	var phaseCPU float64
	var phaseDB sql.DBStats
	var phaseSQL uint64
	var phaseMu sync.Mutex
	var phaseName string
	profile := func(suffix string) error {
		if os.Getenv("CALABI_FLEET_STRESS") != "1" {
			return nil
		}
		f, err := os.Create(filepath.Join(filepath.Dir(path), phaseName+suffix+".alloc"))
		if err != nil {
			return err
		}
		defer f.Close()
		return pprof.Lookup("allocs").WriteTo(f, 0)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != auth {
			http.Error(w, "forbidden", 403)
			return
		}
		var opErr error
		phaseMu.Lock()
		defer phaseMu.Unlock()
		switch r.URL.Path {
		case "/begin":
			services.reads.Store(0)
			services.rows.Store(0)
			idp.reset()
			c.Performance.Stages.Reset()
			rpcStages.reset()
			phaseName = r.URL.Query().Get("phase")
			switch phaseName {
			case "initial", "churn_slow", "churn_fast", "register", "reconnect", "security":
			default:
				phaseName = "initial"
			}
			runtime.GC()
			if err := profile("-before"); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			runtime.ReadMemStats(&phase)
			phaseCPU, _ = performanceProcessUsage()
			if err := flushFleetBackendStats(ctx, []*sql.DB{db}); err != nil {
				http.Error(w, "statistics flush failed", 500)
				return
			}
			phaseDB = db.Stats()
			phaseSQL = driver.operations.Load()
			driver.profile.Store(&fleetSQLProfile{})
			background.reset()
			if phaseTrace != nil {
				phaseTrace.stop()
			}
			phaseTrace = startFleetProcessTrace()
		case "/endpoint":
			for g := 0; g < groups; g++ {
				if opErr = st.UpdateEndpoints(ctx, devices[g].ID, []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")}); opErr != nil {
					break
				}
				notif.Bump(core.MeshnetID(g + 1))
			}
		case "/grant":
			clock.Add(900)
			notif.Bump(1)
		case "/disable":
			opErr = st.SetDisabled(ctx, devices[0].ID, true)
			if opErr == nil {
				notif.Bump(1)
			}
		case "/acl":
			for g := 0; g < groups; g++ {
				if opErr = acl.SetACL(ctx, core.MeshnetID(g+1), core.ACLPolicy{ACLs: []core.ACLRule{{Action: "accept", Src: []string{"no-device"}, Dst: []string{"*"}, Ports: []string{"*"}}}}); opErr != nil {
					break
				}
				notif.Bump(core.MeshnetID(g + 1))
			}
		case "/end":
			if err := flushFleetBackendStats(ctx, []*sql.DB{db}); err != nil {
				http.Error(w, "statistics flush failed", 500)
				return
			}
			backgroundMetrics := background.snapshot()
			if backgroundMetrics != nil && backgroundMetrics["error"] != nil {
				http.Error(w, "background phase failed", http.StatusInternalServerError)
				return
			}
			var processTrace any
			if phaseTrace != nil {
				processTrace = phaseTrace.stop()
			}
			poolNow := db.Stats()
			poolDelta := map[string]any{"wait_count": poolNow.WaitCount - phaseDB.WaitCount, "wait_ms": float64(poolNow.WaitDuration-phaseDB.WaitDuration) / float64(time.Millisecond), "sql_operations": driver.operations.Load() - phaseSQL}
			var mem runtime.MemStats
			runtime.ReadMemStats(&mem)
			cpu, rss := performanceProcessUsage()
			allocated, mallocs := mem.TotalAlloc-phase.TotalAlloc, mem.Mallocs-phase.Mallocs
			runtime.GC()
			runtime.ReadMemStats(&mem)
			if err := profile("-after"); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			calls, peak := idp.metrics()
			w.Header().Set("X-Fleet-Identity", fmt.Sprintf("%d/%d", calls, peak))
			_ = json.NewEncoder(w).Encode(map[string]any{"process_trace": processTrace, "background_baseline": backgroundBaseline, "background_recovery": backgroundMetrics, "stages": c.Performance.Stages.Snapshot(), "rpc_stages": rpcStages.snapshot(), "db_pool": poolNow, "db_phase": poolDelta, "sql_profile": driver.profile.Load().snapshot(), "identity_calls": calls, "identity_peak_100ms": peak, "service_reads": services.reads.Load(), "service_rows": services.rows.Load(), "database": dbDialect, "groups": groups, "services_per_device": serviceCount, "identity_delay_ms": idp.delay.Milliseconds(), "cpu_seconds": cpu - phaseCPU, "allocated_bytes": allocated, "allocations": mallocs, "retained_heap": mem.HeapAlloc, "peak_rss": rss, "streams": c.Performance.Snapshot().Streams, "wire_total": c.Performance.Snapshot().SentProtobufBytes, "sql_total": driver.operations.Load(), "goroutines": runtime.NumGoroutine(), "performance": c.Performance.Snapshot()})
			return
		case "/stop":
			cancel()
		default:
			http.NotFound(w, r)
			return
		}
		if opErr != nil {
			http.Error(w, opErr.Error(), 500)
		}
	})
	httpServer := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}
	defer func() {
		// /stop cancels the fixture context inside its handler. Close would race
		// the still-unflushed success response and turn a clean run into EOF.
		shutdownCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			_ = httpServer.Close()
			t.Errorf("control shutdown: %v", err)
		}
	}()
	go httpServer.Serve(control)
	data, _ := json.Marshal(map[string]any{"Address": ln.Addr().String(), "Control": "http://" + control.Addr().String(), "Auth": auth, "AuthKey": devKey, "Devices": devices, "GrantKey": pub, "GrantTime": clock.Load(), "Groups": groups, "Services": serviceCount})
	// Secrets stay in an isolated temporary fixture, never in logs or results.
	if err := os.WriteFile(path+".tmp", data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		t.Fatal(err)
	}
	<-ctx.Done()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatal("client fixture timed out")
	}
}
