package meshenroll

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/calabi/calabi/apps/client/internal/hostnet"
)

func TestFetchReturnsTheEnrollment(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/mesh/enrollment" || r.Header.Get("Authorization") != "Bearer tk_test" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"enabled":true,"coord_addr":"coord:7014","relay_addr":"derp:3340","node_name":"pixel","org_id":7}`))
	}))
	defer srv.Close()

	enr, err := Fetch(context.Background(), srv.Client(), srv.URL+"/", "tk_test")
	if err != nil {
		t.Fatal(err)
	}
	want := Enrollment{Enabled: true, CoordAddr: "coord:7014", RelayAddr: "derp:3340", NodeName: "pixel", OrgID: 7}
	if enr != want || !enr.WantsRun() {
		t.Fatalf("Fetch = %+v, want %+v", enr, want)
	}
}

// Every failure is an error, never a zero Enrollment that reads as "disabled":
// a poller that took it at face value would tear a live meshnet down over a
// control-plane blip.
func TestFetchFailuresAreErrors(t *testing.T) {
	notOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer notOK.Close()
	garbled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html>`))
	}))
	defer garbled.Close()

	for name, call := range map[string]func() error{
		"no URL":        func() error { _, err := Fetch(context.Background(), http.DefaultClient, "", "tk"); return err },
		"no credential": func() error { _, err := Fetch(context.Background(), notOK.Client(), notOK.URL, ""); return err },
		"non-200":       func() error { _, err := Fetch(context.Background(), notOK.Client(), notOK.URL, "tk"); return err },
		"not JSON":      func() error { _, err := Fetch(context.Background(), garbled.Client(), garbled.URL, "tk"); return err },
	} {
		if call() == nil {
			t.Errorf("%s: Fetch returned no error", name)
		}
	}
}

func TestWantsRunNeedsBothAddresses(t *testing.T) {
	for _, e := range []Enrollment{
		{Enabled: false, CoordAddr: "c:1", RelayAddr: "r:1"},
		{Enabled: true, RelayAddr: "r:1"},
		{Enabled: true, CoordAddr: "c:1"},
	} {
		if e.WantsRun() {
			t.Errorf("%+v wants to run", e)
		}
	}
}

func TestRefreshGate(t *testing.T) {
	denied := fmt.Errorf("mesh: register: %w", status.Error(codes.Unauthenticated, "auth key denied"))
	var calls atomic.Int32
	fresh := func(context.Context) string { calls.Add(1); return "jwt-fresh" }

	var g RefreshGate
	for _, err := range []error{
		errors.New("stream ended"),
		status.Error(codes.Unavailable, "connection reset"),
		status.Error(codes.PermissionDenied, "node disabled"),
	} {
		if g.AfterDenial(context.Background(), err, fresh) {
			t.Errorf("refreshed after %v, which is not a refused credential", err)
		}
	}
	if !g.AfterDenial(context.Background(), denied, fresh) {
		t.Fatal("a refused credential was not refreshed")
	}
	if g.AfterDenial(context.Background(), denied, fresh) {
		t.Fatal("a second refusal inside the cooldown was refreshed again")
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("refresh ran %d times, want 1", n)
	}

	var empty RefreshGate
	if empty.AfterDenial(context.Background(), denied, func(context.Context) string { return "" }) {
		t.Error("a refresh that renewed nothing reported a new credential")
	}
	var none RefreshGate
	if none.AfterDenial(context.Background(), denied, nil) {
		t.Error("a nil refresh reported a new credential")
	}
}

// On a phone the coordinator connection carries the tunnel's control plane, so
// its socket must go through hostnet like the relay's and the direct path's.
func TestDialCoordOpensItsSocketThroughHostnet(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()

	var hooked atomic.Int32
	hostnet.SetSocketHook(func(uintptr) error { hooked.Add(1); return nil })
	t.Cleanup(func() { hostnet.SetSocketHook(nil) })

	conn, err := DialCoord(ln.Addr().String(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Connect()
	deadline := time.Now().Add(3 * time.Second)
	for hooked.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the coordinator connection was opened without the hostnet socket hook")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
