package mesh

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// Every simulated device has its own TCP connection. Changes arrive at a fixed
// offered rate independently of receipt; superseded streams reconnect for a
// full baseline. Registration and stream recovery are measured separately.
func TestFleetStressClient(t *testing.T) {
	if os.Getenv("CALABI_FLEET_STRESS") != "1" || testing.Short() {
		t.Skip("opt-in stress fixture")
	}
	var fixture struct {
		Address, Control, Auth, AuthKey string
		Devices                         []struct {
			ID         int64
			Token, Key string
			Private    []byte
		}
		GrantKey []byte
	}
	b, err := os.ReadFile(os.Getenv("CALABI_FLEET_PROCESS"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Minute)
	defer cancel()
	hc := &http.Client{Timeout: 30 * time.Second}
	control := func(op string) json.RawMessage {
		t.Helper()
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, fixture.Control+"/"+op, nil)
		req.Header.Set("Authorization", fixture.Auth)
		r, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, err := io.ReadAll(r.Body)
		if err != nil || r.StatusCode != 200 {
			t.Fatalf("control %s status=%d err=%v", op, r.StatusCode, err)
		}
		return b
	}
	defer control("stop")
	n := len(fixture.Devices)
	type observed struct {
		ready, version, peers, deny atomic.Int64
		first                       atomic.Int64
	}
	states := make([]observed, n)
	var retries, frames atomic.Int64
	var disabled, acl atomic.Bool
	var mu sync.Mutex
	var failures []string
	var latencies []float64
	updates := map[int]time.Time{}
	var retryCodes = map[string]int{}
	fail := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		if len(failures) < 10 {
			failures = append(failures, err.Error())
		}
	}
	wait := func(label string, timeout time.Duration, ok func() bool) {
		t.Helper()
		deadline := time.Now().Add(timeout)
		for !ok() {
			mu.Lock()
			bad := append([]string(nil), failures...)
			mu.Unlock()
			if len(bad) > 0 {
				t.Fatal(bad)
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s convergence timeout", label)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	all := func(check func(*observed) bool) bool {
		for i := range states {
			if !check(&states[i]) {
				return false
			}
		}
		return true
	}
	var workers sync.WaitGroup
	var stop context.CancelFunc
	start := func() {
		var run context.Context
		run, stop = context.WithCancel(ctx)
		for i := range states {
			states[i].ready.Store(0)
			states[i].first.Store(0)
			states[i].version.Store(0)
			states[i].deny.Store(0)
			workers.Add(1)
			go func(i int) {
				defer workers.Done()
				d := fixture.Devices[i]
				cc, err := grpc.NewClient(fixture.Address, grpc.WithTransportCredentials(insecure.NewCredentials()))
				if err != nil {
					fail(err)
					return
				}
				defer cc.Close()
				rpc := meshpb.NewCoordinatorClient(cc)
				for run.Err() == nil {
					stream, err := rpc.PullNetMap(run, &meshpb.PullNetMapRequest{NodeId: d.ID, SessionToken: d.Token, DeltaNetmap: true}, grpc.WaitForReady(true))
					var decoder meshproto.NetMapDecoder
					var converter netMapConverter
					for err == nil {
						var frame *meshpb.NetMap
						frame, err = stream.Recv()
						if err != nil {
							break
						}
						full, grantOnly, e := decoder.Apply(frame)
						if e != nil {
							fail(e)
							return
						}
						frames.Add(1)
						if grantOnly {
							continue
						}
						model, e := converter.convert(full)
						if e != nil {
							fail(e)
							return
						}
						if model.Self.NodeID != d.ID {
							fail(fmt.Errorf("wrong self"))
							return
						}
						if states[i].ready.Load() == 0 {
							g, e := meshproto.VerifyRelayGrant(ed25519.PublicKey(fixture.GrantKey), full.RelayGrant, time.Now())
							if e != nil || g.Node.String() != d.Key {
								fail(fmt.Errorf("wrong device grant: %v", e))
								return
							}
							states[i].first.Store(time.Now().UnixNano())
							states[i].ready.Store(1)
						}
						states[i].peers.Store(int64(len(model.Peers)))
						if acl.Load() && len(model.Peers) == 0 && model.FilterEnabled && len(model.Filter) == 0 {
							states[i].deny.Store(1)
						}
						peer := model.Self
						found := i == 0
						if i != 0 {
							for _, p := range model.Peers {
								if p.NodeID == fixture.Devices[0].ID {
									peer = p
									found = true
									break
								}
							}
						}
						if disabled.Load() && !found {
							states[i].deny.Store(1)
						}
						if found && len(peer.Endpoints) > 0 {
							v := int(peer.Endpoints[0].Port()) - 40000
							if v > int(states[i].version.Load()) {
								states[i].version.Store(int64(v))
								mu.Lock()
								if sent, ok := updates[v]; ok {
									latencies = append(latencies, float64(time.Since(sent).Microseconds())/1000)
								}
								mu.Unlock()
							}
						}
					}
					if run.Err() != nil {
						return
					}
					if status.Code(err) == codes.PermissionDenied && disabled.Load() && i == 0 {
						states[i].deny.Store(1)
						return
					}
					switch status.Code(err) {
					case codes.Aborted, codes.Canceled, codes.DeadlineExceeded, codes.ResourceExhausted, codes.Unavailable:
						retries.Add(1)
						mu.Lock()
						retryCodes[status.Code(err).String()]++
						mu.Unlock()
						select {
						case <-run.Done():
							return
						case <-time.After(20 * time.Millisecond):
						}
					default:
						fail(fmt.Errorf("stream failed: %s", status.Code(err)))
						return
					}
				}
			}(i)
		}
	}
	defer func() {
		if stop != nil {
			stop()
			workers.Wait()
		}
	}()
	var results []map[string]any
	var started time.Time
	var retriesBefore, framesBefore int64
	begin := func(name string) {
		control("begin?phase=" + name)
		started = time.Now()
		retriesBefore = retries.Load()
		framesBefore = frames.Load()
		mu.Lock()
		latencies = nil
		updates = map[int]time.Time{}
		mu.Unlock()
	}
	end := func(name string) {
		elapsed := time.Since(started)
		server := control("end")
		mu.Lock()
		samples := append([]float64(nil), latencies...)
		mu.Unlock()
		sort.Float64s(samples)
		p95 := 0.0
		if len(samples) > 0 {
			p95 = samples[(len(samples)*95+99)/100-1]
		}
		row := map[string]any{"phase": name, "elapsed_ms": float64(elapsed.Microseconds()) / 1000, "reconnects": retries.Load() - retriesBefore, "received_frames": frames.Load() - framesBefore, "observed_updates": len(samples), "observed_update_p95_ms": p95, "server": server}
		if name == "initial" || name == "reconnect" {
			first := make([]float64, n)
			for i := range states {
				first[i] = float64(states[i].first.Load()-started.UnixNano()) / 1e6
			}
			sort.Float64s(first)
			row["first_map_p95_ms"] = first[(n*95+99)/100-1]
		}
		results = append(results, row)
		b, _ := json.Marshal(row)
		t.Log(string(b))
	}
	begin("initial")
	start()
	wait("initial", 40*time.Second, func() bool {
		return all(func(s *observed) bool { return s.ready.Load() == 1 && s.peers.Load() == int64(n-1) })
	})
	end("initial")
	cc, err := grpc.NewClient(fixture.Address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	rpc := meshpb.NewCoordinatorClient(cc)
	version := 0
	for _, load := range []struct {
		name     string
		count    int
		interval time.Duration
	}{{"churn_slow", 60, time.Second}, {"churn_fast", 200, 100 * time.Millisecond}} {
		begin(load.name)
		schedule := time.Now()
		for j := 0; j < load.count; j++ {
			if delay := time.Until(schedule.Add(time.Duration(j) * load.interval)); delay > 0 {
				time.Sleep(delay)
			}
			version++
			mu.Lock()
			updates[version] = time.Now()
			mu.Unlock()
			_, err = rpc.ReportEndpoints(ctx, &meshpb.ReportEndpointsRequest{NodeId: fixture.Devices[0].ID, SessionToken: fixture.Devices[0].Token, Endpoints: []string{fmt.Sprintf("192.0.2.1:%d", 40000+version)}})
			if err != nil {
				t.Fatal(err)
			}
		}
		last := time.Now()
		wait(load.name, 30*time.Second, func() bool { return all(func(s *observed) bool { return s.version.Load() == int64(version) }) })
		settled := time.Since(last)
		end(load.name)
		results[len(results)-1]["final_convergence_ms"] = float64(settled.Microseconds()) / 1000
		results[len(results)-1]["offered_updates"] = load.count
	}
	stop()
	workers.Wait()
	wait("disconnect", 10*time.Second, func() bool { var s struct{ Streams int64 }; json.Unmarshal(control("end"), &s); return s.Streams == 0 })
	begin("register")
	// A simultaneous proof-based re-registration wave, with no mutation of the
	// fixture device list until every request has finished.
	newTokens := make([]string, n)
	var regWG sync.WaitGroup
	var challengeRetries atomic.Int64
	regTimes := make([]float64, n)
	for i := range fixture.Devices {
		regWG.Add(1)
		go func(i int) {
			defer regWG.Done()
			d := fixture.Devices[i]
			conn, e := grpc.NewClient(fixture.Address, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if e != nil {
				fail(e)
				return
			}
			defer conn.Close()
			r := meshpb.NewCoordinatorClient(conn)
			ch, e := r.GetRegisterChallenge(ctx, &meshpb.GetRegisterChallengeRequest{AuthKey: fixture.AuthKey}, grpc.WaitForReady(true))
			for attempt := 0; status.Code(e) == codes.ResourceExhausted && attempt < 12; attempt++ {
				challengeRetries.Add(1)
				delay := min(time.Duration(1<<attempt)*50*time.Millisecond, time.Second) + time.Duration(i%97)*time.Millisecond
				select {
				case <-ctx.Done():
					fail(ctx.Err())
					return
				case <-time.After(delay):
				}
				ch, e = r.GetRegisterChallenge(ctx, &meshpb.GetRegisterChallengeRequest{AuthKey: fixture.AuthKey}, grpc.WaitForReady(true))
			}
			if e != nil {
				fail(e)
				return
			}
			parsed, e := meshproto.ParseRegisterChallenge(ch.Challenge)
			if e != nil {
				fail(e)
				return
			}
			key, e := meshproto.ParseNodeKey(d.Key)
			if e != nil {
				fail(e)
				return
			}
			var priv [32]byte
			copy(priv[:], d.Private)
			out, e := r.RegisterNode(ctx, &meshpb.RegisterNodeRequest{AuthKey: fixture.AuthKey, NodeKey: d.Key, Name: fmt.Sprintf("process-%d", i), ProtocolVersion: meshproto.ProtocolVersion, ChallengeId: ch.ChallengeId, RegisterProof: meshproto.SealRegisterProof(parsed, key, priv)}, grpc.WaitForReady(true))
			if e != nil {
				fail(e)
				return
			}
			if out.NodeId != d.ID || out.SessionToken == "" {
				fail(fmt.Errorf("registration changed identity"))
				return
			}
			newTokens[i] = out.SessionToken
			regTimes[i] = float64(time.Since(started).Microseconds()) / 1000
		}(i)
	}
	regWG.Wait()
	mu.Lock()
	bad := append([]string(nil), failures...)
	mu.Unlock()
	if len(bad) > 0 {
		t.Fatal(bad)
	}
	end("register")
	sort.Float64s(regTimes)
	results[len(results)-1]["registration_p95_ms"] = regTimes[(n*95+99)/100-1]
	results[len(results)-1]["challenge_limit_retries"] = challengeRetries.Load()
	for i := range fixture.Devices {
		stream, e := rpc.PullNetMap(ctx, &meshpb.PullNetMapRequest{NodeId: fixture.Devices[i].ID, SessionToken: fixture.Devices[i].Token, DeltaNetmap: true})
		if e == nil {
			_, e = stream.Recv()
		}
		if status.Code(e) != codes.Unauthenticated {
			t.Fatalf("old token accepted: %s", status.Code(e))
		}
		fixture.Devices[i].Token = newTokens[i]
	}
	begin("reconnect")
	start()
	wait("reconnect", 40*time.Second, func() bool {
		return all(func(s *observed) bool { return s.ready.Load() == 1 && s.peers.Load() == int64(n-1) })
	})
	end("reconnect")
	begin("security")
	disabled.Store(true)
	control("disable")
	wait("disable", 10*time.Second, func() bool { return all(func(s *observed) bool { return s.deny.Load() == 1 }) })
	// Fresh and superseded tokens must both fail to recover the disabled device.
	stream, e := rpc.PullNetMap(ctx, &meshpb.PullNetMapRequest{NodeId: fixture.Devices[0].ID, SessionToken: fixture.Devices[0].Token, DeltaNetmap: true})
	if e == nil {
		_, e = stream.Recv()
	}
	if status.Code(e) != codes.PermissionDenied {
		t.Fatal("disabled reconnect accepted")
	}
	for i := 1; i < n; i++ {
		states[i].deny.Store(0)
	}
	acl.Store(true)
	control("acl")
	wait("acl", 10*time.Second, func() bool {
		for i := 1; i < n; i++ {
			if states[i].deny.Load() != 1 || states[i].peers.Load() != 0 {
				return false
			}
		}
		return true
	})
	end("security")
	stop()
	workers.Wait()
	cc.Close()
	wait("drain", 10*time.Second, func() bool { var s struct{ Streams int64 }; json.Unmarshal(control("end"), &s); return s.Streams == 0 })
	mu.Lock()
	bad = append([]string(nil), failures...)
	mu.Unlock()
	if len(bad) > 0 {
		t.Fatal(bad)
	}
	out := map[string]any{"devices": n, "phases": results, "retry_codes": retryCodes, "drained": json.RawMessage(control("end"))}
	b, _ = json.MarshalIndent(out, "", "  ")
	if err = os.WriteFile(os.Getenv("CALABI_FLEET_RESULT"), b, 0600); err != nil {
		t.Fatal(err)
	}
}
