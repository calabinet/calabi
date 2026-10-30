package rpc

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	entsql "entgo.io/ent/dialect/sql"
	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	"github.com/calabinet/calabi/apps/calabi-coord/internal/platform/store"
	"github.com/calabinet/calabi/apps/calabi-coord/internal/platform/store/ent"
)

func TestFleetIdentityDelayFailsClosed(t *testing.T) {
	f := &fleetIdentityRPC{groups: 2, delay: time.Second}
	f.reset()
	a := f.authenticator(slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.Resolve(ctx, "fleet-org-1"); err == nil {
		t.Fatal("canceled identity call admitted device")
	}
	if err := a.Reauthorize(ctx, 1, "user:1"); err == nil {
		t.Fatal("canceled membership check admitted device")
	}
	deadline, release := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer release()
	if err := a.Reauthorize(deadline, 1, "user:1"); err == nil || deadline.Err() != context.DeadlineExceeded {
		t.Fatal("identity timeout did not fail closed")
	}
	f.active.Store(false)
	if _, err := a.Resolve(context.Background(), "unknown"); !errors.Is(err, core.ErrAuthDenied) {
		t.Fatalf("invalid credential: %v", err)
	}
	if err := a.Reauthorize(context.Background(), 2, "user:1"); !errors.Is(err, core.ErrAuthDenied) {
		t.Fatalf("cross-organization principal: %v", err)
	}
}

func TestFleetPostgresFailureAndServiceScope(t *testing.T) {
	if os.Getenv("CALABI_FLEET_PG_DSN") == "" || testing.Short() {
		t.Skip("isolated PostgreSQL opt-in")
	}
	ctx := context.Background()
	db, dialect := fleetDatabase(t, ctx)
	s := store.New(ent.NewClient(ent.Driver(entsql.OpenDB(dialect, db))))
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	c := &core.Coordinator{Nodes: s, Services: s, IPAM: core.NewMemIPAM()}
	key, _ := newKeyPair(t)
	in := core.RegisterInput{Meshnet: 1, NodeKey: key, Name: "a"}
	n, err := c.Register(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, _ := newKeyPair(t)
	if _, err := c.Register(ctx, core.RegisterInput{Meshnet: 2, NodeKey: otherKey, Name: "other-org"}); err != nil {
		t.Fatal(err)
	}
	names, err := s.ListRegistrationNames(ctx, 1, 0)
	if err != nil || len(names) != 1 || names[0] != "a" {
		t.Fatalf("PostgreSQL name scope: %v %v", names, err)
	}
	names, err = s.ListRegistrationNames(ctx, 1, n.ID)
	if err != nil || len(names) != 0 {
		t.Fatalf("PostgreSQL self exclusion: %v %v", names, err)
	}
	if _, err := s.TouchRegistration(ctx, n); err != nil {
		t.Fatal(err)
	}
	wrong := *n
	wrong.Meshnet = 2
	if _, err := s.TouchRegistration(ctx, &wrong); err == nil {
		t.Fatal("PostgreSQL cross-org touch succeeded")
	}
	for _, v := range []core.Service{{Meshnet: 1, NodeID: n.ID, Name: "admin", Proto: "tcp", Port: 80, Approved: true, Source: core.ServiceSourceConsole}, {Meshnet: 2, NodeID: n.ID + 1, Name: "foreign", Proto: "tcp", Port: 81}} {
		if _, err := s.CreateService(ctx, v); err != nil {
			t.Fatal(err)
		}
	}
	in.DeclaredServices = []core.Service{{Name: "admin", Proto: "tcp", Port: 9999}, {Name: "device", Proto: "tcp", Port: 82}}
	if _, err := c.Register(ctx, in); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListNodeServices(ctx, 1, n.ID)
	if err != nil || len(rows) != 2 {
		t.Fatalf("scoped query: %v %v", rows, err)
	}
	for _, v := range rows {
		if v.Name == "admin" && (v.Port != 80 || !v.Approved || !v.FromConsole()) {
			t.Fatal("admin decision changed")
		}
	}
	rows, err = s.ListNodeServices(ctx, 2, n.ID)
	if err != nil || len(rows) != 0 {
		t.Fatal("cross-organization query leaked")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if n, _, err := c.RegisterWithChange(ctx, in); err == nil || n != nil {
		t.Fatal("database failure admitted registration")
	}
}
