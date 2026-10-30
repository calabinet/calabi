package rpc

import (
	"context"
	"fmt"
	"os"
	"testing"

	entsql "entgo.io/ent/dialect/sql"
	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	"github.com/calabinet/calabi/apps/calabi-coord/internal/platform/store"
	"github.com/calabinet/calabi/apps/calabi-coord/internal/platform/store/ent"
)

// Isolate declaration-read cost from subscriptions and repeated registration.
// Both paths use the same real PostgreSQL data and production store methods.
func BenchmarkFleetPostgresServiceRead(b *testing.B) {
	if os.Getenv("CALABI_FLEET_PG_DSN") == "" {
		b.Skip("isolated PostgreSQL opt-in")
	}
	ctx := context.Background()
	db, dialect := fleetDatabase(b, ctx)
	s := store.New(ent.NewClient(ent.Driver(entsql.OpenDB(dialect, db))))
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		b.Fatal(err)
	}
	for node := int64(1); node <= 1000; node++ {
		for j := 0; j < 2; j++ {
			if _, err := s.CreateService(ctx, core.Service{Meshnet: 1, NodeID: node, Name: fmt.Sprintf("svc-%d", j), Proto: "tcp", Port: 8000 + j, Approved: true}); err != nil {
				b.Fatal(err)
			}
		}
	}
	for _, scoped := range []bool{false, true} {
		name := "organization"
		if scoped {
			name = "device"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var rows []core.Service
				var err error
				want := 2000
				if scoped {
					rows, err = s.ListNodeServices(ctx, 1, int64(i%1000+1))
					want = 2
				} else {
					rows, err = s.ListServices(ctx, 1)
				}
				if err != nil || len(rows) != want {
					b.Fatalf("read: rows=%d error=%v", len(rows), err)
				}
			}
		})
	}
}
