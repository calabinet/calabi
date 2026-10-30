package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNeighborMalformedResultFailsClosed(t *testing.T) {
	for _, body := range []string{"not JSON", "null"} {
		n := &neighborControl{ctx: context.Background(), dir: t.TempDir(), epoch: 1, millis: 100}
		if err := os.WriteFile(filepath.Join(n.dir, "result-1.json"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if n.snapshot()["error"] == nil {
			t.Fatal("malformed worker result reported success")
		}
	}
}

type neighborCheck struct {
	Scheduled, Completed, Dropped, PID int
	Cancelled                          bool
	Read, Write, Errors                int
}

// A version may expire after the caller's check but before the send goroutine
// enters Send. Count the two allowed outcomes without assuming scheduler order.
type attributionUnsentStream struct {
	*snapshotStream
	sends atomic.Int64
}

func (s *attributionUnsentStream) Send(*meshpb.NetMap) error { s.sends.Add(1); return nil }
func TestFleetSupersededBeforeSendAttribution(t *testing.T) {
	s, _, _, _ := sharedMapFixture(t)
	stream := &attributionUnsentStream{snapshotStream: &snapshotStream{ctx: context.Background()}}
	changed := make(chan struct{})
	close(changed)
	aborted, superseded := 0, 0
	for i := 0; i < 1000; i++ {
		err := s.sendNetMapPayload(stream, &meshpb.NetMap{}, changed)
		switch {
		case errors.Is(err, errMapSuperseded):
			superseded++
		case status.Code(err) == codes.Aborted:
			aborted++
		default:
			t.Fatalf("unexpected result: %v", err)
		}
	}
	if stream.sends.Load() != 0 {
		t.Fatal("superseded map reached transport")
	}
	t.Logf("already superseded before transport: aborted=%d superseded=%d sends=%d", aborted, superseded, stream.sends.Load())
}

func TestNeighborSubprocessCancellation(t *testing.T) {
	if os.Getenv("CALABI_FLEET_PG_DSN") == "" || testing.Short() {
		t.Skip("isolated PostgreSQL opt-in")
	}
	t.Setenv("CALABI_FLEET_BACKGROUND_RPS", "100")
	t.Setenv("CALABI_FLEET_WINDOW_MS", "10000")
	n := startNeighborControl(t, context.Background(), "separate")
	n.begin()
	n.stop()
	select {
	case <-n.exited:
	default:
		t.Fatal("child process leaked")
	}
}

func normalizeNeighborResult(r map[string]any) (neighborCheck, error) {
	var wire struct {
		Scheduled, Completed, Dropped, PID int
		Cancelled                          bool
		Groups                             map[string]struct {
			Errors int
			Total  struct{ Count int } `json:"end_to_end"`
		} `json:"read_write"`
	}
	b, err := json.Marshal(r)
	if err != nil {
		return neighborCheck{}, err
	}
	if err = json.Unmarshal(b, &wire); err != nil {
		return neighborCheck{}, err
	}
	return neighborCheck{wire.Scheduled, wire.Completed, wire.Dropped, wire.PID, wire.Cancelled, wire.Groups["read"].Total.Count, wire.Groups["write"].Total.Count, wire.Groups["read"].Errors + wire.Groups["write"].Errors}, nil
}

func TestNeighborScheduleDeterministicAndMixed(t *testing.T) {
	a, hash := neighborSchedule(400, 10000, 20261030)
	b, hash2 := neighborSchedule(400, 10000, 20261030)
	if !reflect.DeepEqual(a, b) || hash != hash2 {
		t.Fatal("seed is not reproducible")
	}
	c, hash3 := neighborSchedule(400, 10000, 20261031)
	if reflect.DeepEqual(a, c) || hash == hash3 {
		t.Fatal("different seeds give same schedule")
	}
	writes := 0
	services := [4]int{}
	firstWrites := 0
	for i, j := range a {
		if j.Row < 1 || j.Row > 10000 || j.Offset != time.Duration(i)*time.Second/400 {
			t.Fatal("invalid scheduled request")
		}
		services[j.Service]++
		if j.Write {
			writes++
			if i < 64 {
				firstWrites++
			}
		}
	}
	if writes != 1000 || services != [4]int{1000, 1000, 1000, 1000} || firstWrites == 0 || firstWrites == 64 {
		t.Fatalf("bad mix: %d %v %d", writes, services, firstWrites)
	}
}

func TestNeighborFixedWindowAndProcessIsolation(t *testing.T) {
	if os.Getenv("CALABI_FLEET_PG_DSN") == "" || testing.Short() {
		t.Skip("isolated PostgreSQL opt-in")
	}
	t.Setenv("CALABI_FLEET_BACKGROUND_RPS", "100")
	t.Setenv("CALABI_FLEET_WINDOW_MS", "800")
	for _, mode := range []string{"inline", "separate"} {
		t.Run(mode, func(t *testing.T) {
			n := startNeighborControl(t, context.Background(), mode)
			defer n.stop()
			var previousHash any
			for i := 0; i < 2; i++ {
				n.begin()
				r := n.snapshot()
				if r["error"] != nil {
					t.Fatal(r)
				}
				// JSON normalization gives identical assertions for local and subprocess results.
				data, err := normalizeNeighborResult(r)
				if err != nil {
					t.Fatal(err)
				}
				if data.Scheduled != 80 || data.Completed != 80 || data.Dropped != 0 || data.Cancelled || data.Read != 60 || data.Write != 20 || data.Errors != 0 {
					t.Fatalf("lost fixed arrivals: %+v", data)
				}
				if (data.PID == os.Getpid()) != (mode == "inline") {
					t.Fatal("process isolation not exercised")
				}
				if previousHash != nil && previousHash != r["schedule_sha256"] {
					t.Fatal("phase seed changed")
				}
				previousHash = r["schedule_sha256"]
			}
		})
	}
}

func TestNeighborCancellationAndDatabaseFailure(t *testing.T) {
	if os.Getenv("CALABI_FLEET_PG_DSN") == "" || testing.Short() {
		t.Skip("isolated PostgreSQL opt-in")
	}
	pools := neighborPools(t, context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := runNeighborWindow(ctx, pools, time.Now(), 100, 500, 7)
	if r["cancelled"] != true || r["completed"].(int)+r["dropped"].(int) != 50 {
		t.Fatal("cancel lost arrivals")
	}
	for _, p := range pools {
		p.Close()
	}
	r = runNeighborWindow(context.Background(), pools, time.Now(), 100, 200, 7)
	v, err := normalizeNeighborResult(r)
	if err != nil {
		t.Fatal(err)
	}
	if v.Completed != 20 || v.Errors != 20 || v.Dropped != 0 {
		t.Fatalf("DB failure hidden: %+v", v)
	}
}
