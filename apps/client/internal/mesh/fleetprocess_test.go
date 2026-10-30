package mesh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestFleetProcessClient(t *testing.T) {
	path := os.Getenv("CALABI_FLEET_PROCESS")
	if path == "" || testing.Short() {
		t.Skip("opt-in separate-process fixture")
	}
	var fixture struct {
		Address, Control, Auth string
		Devices                []struct {
			ID         int64
			Token, Key string
		}
		GrantKey  []byte
		GrantTime int64
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	httpClient := &http.Client{Timeout: 30 * time.Second}
	control := func(op string) json.RawMessage {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, fixture.Control+"/"+op, bytes.NewReader(nil))
		req.Header.Set("Authorization", fixture.Auth)
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			t.Fatalf("control %s: %s", op, data)
		}
		return data
	}
	defer control("stop")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	conn, err := grpc.NewClient(fixture.Address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := meshpb.NewCoordinatorClient(conn)
	type state struct {
		stream    meshpb.Coordinator_PullNetMapClient
		decoder   meshproto.NetMapDecoder
		model     NetMap
		converter netMapConverter
	}
	states := make([]state, len(fixture.Devices))
	var wire uint64
	var results []map[string]any
	receive := func(i int, op string) (int, error) {
		s := &states[i]
		frame, err := s.stream.Recv()
		if op == "disable" && i == 0 {
			if status.Code(err) != codes.PermissionDenied {
				return 0, fmt.Errorf("disabled stream: %v", err)
			}
			return 0, nil
		}
		if err != nil {
			return 0, err
		}
		n := proto.Size(frame)
		full, grantOnly, err := s.decoder.Apply(frame)
		if err != nil {
			return 0, err
		}
		if grantOnly {
			s.model.RelayGrant = full.RelayGrant
		} else {
			s.model, err = s.converter.convert(full)
			if err != nil {
				return 0, err
			}
		}
		want := len(states) - 1
		if op == "disable" {
			want--
		}
		if op == "acl" {
			want = 0
		}
		if len(s.model.Peers) != want {
			return 0, fmt.Errorf("%s peers=%d want=%d", op, len(s.model.Peers), want)
		}
		if op == "acl" && (!s.model.FilterEnabled || len(s.model.Filter) != 0) {
			return 0, fmt.Errorf("ACL not revoked")
		}
		if op == "grant" {
			g, err := meshproto.VerifyRelayGrant(ed25519.PublicKey(fixture.GrantKey), full.RelayGrant, time.Unix(fixture.GrantTime+900, 0))
			if err != nil || g.Node.String() != fixture.Devices[i].Key || !grantOnly {
				return 0, fmt.Errorf("independent grant failed: %v", err)
			}
		}
		if op == "disable" {
			for _, p := range s.model.Peers {
				if p.NodeID == fixture.Devices[0].ID {
					return 0, fmt.Errorf("revoked peer retained")
				}
			}
		}
		return n, nil
	}
	for _, op := range []string{"initial", "endpoint", "grant", "disable", "acl"} {
		control("begin")
		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)
		started := time.Now()
		if op == "initial" {
			for i, device := range fixture.Devices {
				states[i].stream, err = client.PullNetMap(ctx, &meshpb.PullNetMapRequest{NodeId: device.ID, SessionToken: device.Token, DeltaNetmap: true})
				if err != nil {
					t.Fatal(err)
				}
				n, err := receive(i, op)
				if err != nil {
					t.Fatal(err)
				}
				wire += uint64(n)
			}
		} else {
			control(op)
			var wg sync.WaitGroup
			var mu sync.Mutex
			var failure error
			var samples []float64
			for i := range states {
				if op == "acl" && i == 0 {
					continue
				}
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					n, err := receive(i, op)
					mu.Lock()
					defer mu.Unlock()
					if err != nil {
						failure = err
					}
					wire += uint64(n)
					samples = append(samples, float64(time.Since(started).Microseconds())/1000)
				}(i)
			}
			wg.Wait()
			if failure != nil {
				t.Fatal(failure)
			}
			sort.Float64s(samples)
			t.Logf("%s p95_ms=%.3f max_ms=%.3f", op, samples[(len(samples)*95+99)/100-1], samples[len(samples)-1])
		}
		elapsed := time.Since(started)
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		allocated, mallocs := after.TotalAlloc-before.TotalAlloc, after.Mallocs-before.Mallocs
		runtime.GC()
		runtime.ReadMemStats(&after)
		server := control("end")
		row := map[string]any{"phase": op, "elapsed_ms": float64(elapsed.Microseconds()) / 1000, "client_allocated_bytes": allocated, "client_allocations": mallocs, "client_retained_heap": after.HeapAlloc, "wire_total": wire, "server": server}
		results = append(results, row)
		data, _ := json.Marshal(row)
		t.Log(string(data))
	}
	cancel()
	conn.Close()
	// An independent baseline must also prove that disconnect releases streams.
	for deadline := time.Now().Add(5 * time.Second); ; {
		var stat struct{ Streams int64 }
		json.Unmarshal(control("end"), &stat)
		if stat.Streams == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server streams did not drain")
		}
		time.Sleep(10 * time.Millisecond)
	}
	data, _ := json.MarshalIndent(results, "", "  ")
	if err := os.WriteFile(os.Getenv("CALABI_FLEET_RESULT"), data, 0600); err != nil {
		t.Fatal(err)
	}
	runtime.KeepAlive(states)
}
