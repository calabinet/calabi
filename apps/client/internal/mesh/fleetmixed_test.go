package mesh

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// Unlike the component benchmark, each device subscribes immediately after its
// registration. Stream failures restart registration too, with a 1..60 second
// exponential backoff, exercising the registration/notification feedback loop.
func TestFleetMixedReconnectClient(t *testing.T) {
	if os.Getenv("CALABI_FLEET_MIXED") != "1" || testing.Short() {
		t.Skip("opt-in mixed recovery")
	}
	var f struct {
		Address, Control, Auth, AuthKey string
		Groups, Services                int
		Devices                         []struct {
			ID         int64
			Token, Key string
			Private    []byte
			Group      int
			AuthKey    string
		}
	}
	b, err := os.ReadFile(os.Getenv("CALABI_FLEET_PROCESS"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if f.Groups == 0 {
		f.Groups = 1
	}
	groupByID := map[int64]int{}
	for i := range f.Devices {
		if f.Devices[i].AuthKey == "" {
			f.Devices[i].AuthKey = f.AuthKey
		}
		groupByID[f.Devices[i].ID] = f.Devices[i].Group
	}
	var declarations []DeclaredService
	for j := 0; j < f.Services; j++ {
		declarations = append(declarations, DeclaredService{Name: fmt.Sprintf("svc-%d", j), Proto: "tcp", Port: 8000 + j})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	hc := &http.Client{Timeout: 30 * time.Second}
	control := func(op string) json.RawMessage {
		t.Helper()
		requestCtx := ctx
		if (op == "stop" || op == "end") && ctx.Err() != nil {
			var release context.CancelFunc
			requestCtx, release = context.WithTimeout(context.Background(), 10*time.Second)
			defer release()
		}
		req, _ := http.NewRequestWithContext(requestCtx, http.MethodPost, f.Control+"/"+op, nil)
		req.Header.Set("Authorization", f.Auth)
		r, e := hc.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer r.Body.Close()
		data, e := io.ReadAll(r.Body)
		if e != nil || r.StatusCode != 200 {
			t.Fatalf("control failed %s status=%d: %v", op, r.StatusCode, e)
		}
		return data
	}
	defer control("stop")
	// Model a fleet that has already reported the current client's metadata.
	// Keep the original unprimed mode to exercise real changes on reconnect too.
	stable := os.Getenv("CALABI_FLEET_STABLE_RECONNECT") == "1"
	rotateDisco := os.Getenv("CALABI_FLEET_ROTATE_DISCO") == "1"
	if stable {
		cc, err := grpc.NewClient(f.Address, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			t.Fatal(err)
		}
		defer cc.Close()
		for i, d := range f.Devices {
			key, err := meshproto.ParseNodeKey(d.Key)
			if err != nil {
				t.Fatal(err)
			}
			var private PrivateKey
			copy(private[:], d.Private)
			reg, err := NewCoordClient(cc).Register(ctx, RegisterParams{AuthKey: d.AuthKey, NodeKey: key, NodePrivate: private, NodeID: d.ID, Reauth: true, Name: fmt.Sprintf("process-%d", i), Services: declarations})
			if err != nil || reg.NodeID != d.ID {
				t.Fatalf("prime device %d: %v", i, err)
			}
		}
	}
	type state struct {
		registered, connected, latest, denied, empty atomic.Bool
		firstMap, latestMap                          atomic.Int64
	}
	states := make([]state, len(f.Devices))
	var clientTimings fleetClientTimings
	var rpcDiagnostics fleetRPCDiagnostics
	var registrations, lastRegistration, firstMapTimeouts atomic.Int64
	var disabled, denyACL atomic.Bool
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errors []string
	retryCodes := map[string]int{}
	fail := func(e error) {
		mu.Lock()
		defer mu.Unlock()
		if len(errors) < 10 {
			errors = append(errors, e.Error())
		}
	}
	run, stop := context.WithCancel(ctx)
	defer func() { stop(); wg.Wait() }()
	control("begin?phase=reconnect")
	started := time.Now()
	connectSpreadMS, _ := strconv.Atoi(os.Getenv("CALABI_FLEET_CONNECT_SPREAD_MS"))
	if connectSpreadMS < 0 || connectSpreadMS > 5000 {
		t.Fatal("connect spread must be 0..5000 ms")
	}
	for i := range states {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d := f.Devices[i]
			if connectSpreadMS > 0 {
				select {
				case <-run.Done():
					return
				case <-time.After(time.Duration(connectSpreadMS*i/len(states)) * time.Millisecond):
				}
			}
			cc, e := grpc.NewClient(f.Address, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithUnaryInterceptor(rpcDiagnostics.interceptor(t)), grpc.WithStreamInterceptor(rpcDiagnostics.streamInterceptor()))
			if e != nil {
				fail(e)
				return
			}
			defer func() { _ = cc.Close() }()
			client := NewCoordClient(cc)
			key, e := meshproto.ParseNodeKey(d.Key)
			if e != nil {
				fail(e)
				return
			}
			var private PrivateKey
			copy(private[:], d.Private)
			backoff := time.Second
			maxBackoff := time.Minute
			if os.Getenv("CALABI_FLEET_DESKTOP_RETRY") == "1" {
				backoff, maxBackoff = 2*time.Second, 30*time.Second
			}
			random := rand.New(rand.NewPCG(uint64(i+1), 19))
			for run.Err() == nil {
				params := RegisterParams{AuthKey: d.AuthKey, NodeKey: key, NodePrivate: private, NodeID: d.ID, Reauth: true, Name: fmt.Sprintf("process-%d", i), Services: declarations}
				if rotateDisco {
					disco, err := GenerateDiscoKey()
					if err != nil {
						fail(err)
						return
					}
					params.DiscoKey = disco.Public()
				}
				registerStart := time.Now()
				reg, e := client.Register(run, params)
				clientTimings.observe("register/"+status.Code(e).String(), registerStart)
				if e == nil {
					if reg.NodeID != d.ID {
						fail(fmt.Errorf("identity changed"))
						return
					}
					registrations.Add(1)
					lastRegistration.Store(time.Now().UnixNano())
					states[i].registered.Store(true)
					watch := client.watchUpdates
					if os.Getenv("CALABI_FLEET_REAUTH_WATCH") != "0" {
						watch = func(ctx context.Context, nodeID int64, onMap func(NetMap), onGrant func([]byte)) error {
							return client.watchReauthenticated(ctx, nodeID, watchRecovery{onTimeout: func() { firstMapTimeouts.Add(1) }, interrupted: func() { states[i].connected.Store(false); states[i].latestMap.Store(0) }, refresh: func(ctx context.Context) error {
								states[i].connected.Store(false)
								states[i].latestMap.Store(0)
								mu.Lock()
								retryCodes["SubscriptionRecovery"]++
								mu.Unlock()
								refreshStart := time.Now()
								fresh, err := client.Register(ctx, params)
								clientTimings.observe("refresh/"+status.Code(err).String(), refreshStart)
								if err != nil {
									return err
								}
								if fresh.NodeID != d.ID || fresh.Overlay != reg.Overlay {
									return fmt.Errorf("identity changed during recovery")
								}
								registrations.Add(1)
								lastRegistration.Store(time.Now().UnixNano())
								return nil
							}}, onMap, onGrant)
						}
					}
					e = watch(run, d.ID, func(nm NetMap) {
						if !disabled.Load() && !denyACL.Load() && len(nm.Peers) != len(f.Devices)/f.Groups-1 {
							fail(fmt.Errorf("incomplete organization map"))
							return
						}
						for _, peer := range nm.Peers {
							g, ok := groupByID[peer.NodeID]
							if !ok || g != d.Group {
								fail(fmt.Errorf("cross-organization peer"))
								return
							}
							if len(peer.Services) != f.Services {
								fail(fmt.Errorf("approved service declarations missing"))
								return
							}
						}
						if rotateDisco && nm.Self.DiscoKey != params.DiscoKey {
							fail(fmt.Errorf("current discovery key not published"))
							return
						}
						if nm.Self.NodeID != d.ID || nm.Self.NodeKey != key {
							fail(fmt.Errorf("wrong self"))
							return
						}
						elapsed := time.Since(started).Nanoseconds()
						states[i].firstMap.CompareAndSwap(0, elapsed)
						peer := nm.Self
						found := i == d.Group
						if i != d.Group {
							for _, p := range nm.Peers {
								if p.NodeID == f.Devices[d.Group].ID {
									peer = p
									found = true
									break
								}
							}
						}
						isLatest := found && len(peer.Endpoints) > 0 && peer.Endpoints[0].String() == "192.0.2.1:41641"
						states[i].latest.Store(isLatest)
						if isLatest {
							states[i].latestMap.CompareAndSwap(0, elapsed)
						}
						if disabled.Load() && !found && d.Group == 0 {
							states[i].denied.Store(true)
						}
						if denyACL.Load() && len(nm.Peers) == 0 && nm.FilterEnabled && len(nm.Filter) == 0 {
							states[i].empty.Store(true)
						}
						// Publish readiness after all timing and map state is visible.
						states[i].connected.Store(true)
					}, func([]byte) {})
				}
				states[i].connected.Store(false)
				states[i].latestMap.Store(0)
				_ = cc.Close() // Real outer reconnects rebuild the control transport too.
				if run.Err() != nil {
					return
				}
				if status.Code(e) == codes.PermissionDenied && disabled.Load() && i == 0 {
					states[i].denied.Store(true)
					return
				}
				switch status.Code(e) {
				case codes.Aborted, codes.Canceled, codes.DeadlineExceeded, codes.Unavailable, codes.ResourceExhausted:
					mu.Lock()
					retryCodes[status.Code(e).String()]++
					mu.Unlock()
				default:
					fail(fmt.Errorf("unexpected lifecycle failure: %s", status.Code(e)))
					return
				}
				delay := backoff
				if os.Getenv("CALABI_FLEET_RETRY_JITTER") == "1" {
					delay = reconnectDelay(backoff, random.Int64N)
				}
				backoffStart := time.Now()
				select {
				case <-run.Done():
					return
				case <-time.After(delay):
				}
				clientTimings.observe("outer_backoff", backoffStart)
				backoff = min(2*backoff, maxBackoff)
				cc, e = grpc.NewClient(f.Address, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithUnaryInterceptor(rpcDiagnostics.interceptor(t)), grpc.WithStreamInterceptor(rpcDiagnostics.streamInterceptor()))
				if e != nil {
					fail(e)
					return
				}
				client = NewCoordClient(cc)
			}
		}(i)
	}
	wait := func(label string, check func() bool) {
		t.Helper()
		nextLog := time.Now().Add(15 * time.Second)
		for !check() {
			if time.Now().After(nextLog) {
				connected, latest := 0, 0
				for i := range states {
					if states[i].connected.Load() {
						connected++
					}
					if states[i].latest.Load() {
						latest++
					}
				}
				t.Logf("%s: registrations=%d connected=%d latest=%d", label, registrations.Load(), connected, latest)
				nextLog = time.Now().Add(15 * time.Second)
			}
			mu.Lock()
			bad := append([]string(nil), errors...)
			mu.Unlock()
			if len(bad) > 0 {
				failure, _ := json.MarshalIndent(map[string]any{"failed_phase": label, "errors": bad, "rpc_diagnostics": rpcDiagnostics.snapshot(), "elapsed_ms": float64(time.Since(started).Milliseconds()), "server": json.RawMessage(control("end"))}, "", "  ")
				_ = os.WriteFile(os.Getenv("CALABI_FLEET_RESULT"), failure, 0600)
				t.Fatal(bad)
			}
			select {
			case <-ctx.Done():
				mu.Lock()
				codes := make(map[string]int, len(retryCodes))
				for code, count := range retryCodes {
					codes[code] = count
				}
				mu.Unlock()
				failure, _ := json.MarshalIndent(map[string]any{"failed_phase": label, "first_map_timeouts": firstMapTimeouts.Load(), "reauthenticated_watch": os.Getenv("CALABI_FLEET_REAUTH_WATCH") != "0", "desktop_retry": os.Getenv("CALABI_FLEET_DESKTOP_RETRY") == "1", "devices": len(states), "groups": f.Groups, "retry_jitter": os.Getenv("CALABI_FLEET_RETRY_JITTER") == "1", "retry_codes": codes, "registrations": registrations.Load(), "elapsed_ms": float64(time.Since(started).Milliseconds()), "server": json.RawMessage(control("end"))}, "", "  ")
				_ = os.WriteFile(os.Getenv("CALABI_FLEET_RESULT"), failure, 0600)
				t.Fatalf("%s did not converge: %v", label, ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	wait("registration", func() bool {
		for i := range states {
			if !states[i].registered.Load() {
				return false
			}
		}
		return true
	})
	registeredAllMS := float64(time.Since(started).Microseconds()) / 1000
	control("endpoint")
	endpointUpdatedMS := float64(time.Since(started).Microseconds()) / 1000
	var allLatestMS float64
	wait("stable mixed recovery", func() bool {
		for i := range states {
			if !states[i].latest.Load() || !states[i].connected.Load() {
				return false
			}
		}
		if allLatestMS == 0 {
			allLatestMS = float64(time.Since(started).Microseconds()) / 1000
		}
		return time.Since(time.Unix(0, lastRegistration.Load())) > 2*time.Second
	})
	recovered := time.Since(started)
	firstMaps, finalMaps := make([]float64, len(states)), make([]float64, len(states))
	for i := range states {
		firstMaps[i] = float64(states[i].firstMap.Load()) / 1e6
		finalMaps[i] = float64(states[i].latestMap.Load()) / 1e6
		if firstMaps[i] <= 0 || finalMaps[i] <= 0 {
			t.Fatal("missing recovery timing sample")
		}
	}
	recoveryQuantiles := map[string]any{"first_map": fleetQuantiles(firstMaps), "final_latest_map": fleetQuantiles(finalMaps)}
	phaseClientTimings := clientTimings.snapshot()
	phaseRPCDiagnostics := rpcDiagnostics.snapshot()
	recoveryMetrics := control("end")
	windowRPCDiagnostics := rpcDiagnostics.snapshot()
	windowClientTimings := clientTimings.snapshot()
	disabled.Store(true)
	control("disable")
	wait("disable", func() bool {
		for i := range states {
			if f.Devices[i].Group != 0 {
				continue
			}
			if !states[i].denied.Load() {
				return false
			}
		}
		return true
	})
	denyACL.Store(true)
	control("acl")
	wait("ACL", func() bool {
		for i := 1; i < len(states); i++ {
			if !states[i].empty.Load() {
				return false
			}
		}
		return true
	})
	stop()
	wg.Wait()
	wait("drain", func() bool { var s struct{ Streams int64 }; json.Unmarshal(control("end"), &s); return s.Streams == 0 })
	mu.Lock()
	bad := append([]string(nil), errors...)
	mu.Unlock()
	if len(bad) > 0 {
		t.Fatal(bad)
	}
	out := map[string]any{"connect_spread_ms": connectSpreadMS, "milestones_ms": map[string]float64{"all_registered": registeredAllMS, "endpoint_updates_done": endpointUpdatedMS, "all_latest_observed": allLatestMS}, "rpc_diagnostics": phaseRPCDiagnostics, "window_rpc_diagnostics": windowRPCDiagnostics, "window_client_stages": windowClientTimings, "recovery_quantiles": recoveryQuantiles, "client_stages": phaseClientTimings, "first_map_timeouts": firstMapTimeouts.Load(), "reauthenticated_watch": os.Getenv("CALABI_FLEET_REAUTH_WATCH") != "0", "desktop_retry": os.Getenv("CALABI_FLEET_DESKTOP_RETRY") == "1", "groups": f.Groups, "services_per_device": f.Services, "retry_jitter": os.Getenv("CALABI_FLEET_RETRY_JITTER") == "1", "devices": len(states), "primed_metadata": stable, "rotate_disco": rotateDisco, "stable_recovery_ms": float64(recovered.Microseconds()) / 1000, "successful_registrations": registrations.Load(), "retry_codes": retryCodes, "server_recovery": recoveryMetrics, "drained": json.RawMessage(control("end")), "disable_and_acl_passed": true}
	b, _ = json.MarshalIndent(out, "", "  ")
	t.Log(string(b))
	if err = os.WriteFile(os.Getenv("CALABI_FLEET_RESULT"), b, 0600); err != nil {
		t.Fatal(err)
	}
}
