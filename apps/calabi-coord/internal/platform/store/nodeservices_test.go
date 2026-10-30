package store

import (
	"context"
	"testing"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
)

func TestNodeServicesPreserveReconciliationSecurity(t *testing.T) {
	s := newTestStore(t)
	c := &core.Coordinator{Nodes: s, Services: s, IPAM: core.NewMemIPAM()}
	ctx := context.Background()
	in := core.RegisterInput{Meshnet: 1, NodeKey: key(11), Name: "a"}
	a, err := c.Register(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Register(ctx, core.RegisterInput{Meshnet: 2, NodeKey: key(12), Name: "b"})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []core.Service{
		{Meshnet: 1, NodeID: a.ID, Name: "admin", Proto: "tcp", Port: 80, Approved: true, Source: core.ServiceSourceConsole},
		{Meshnet: 1, NodeID: a.ID, Name: "node", Proto: "tcp", Port: 81, Approved: true},
		{Meshnet: 1, NodeID: a.ID, Name: "pending", Proto: "tcp", Port: 82, Approved: false},
		{Meshnet: 2, NodeID: b.ID, Name: "foreign", Proto: "tcp", Port: 83, Approved: true},
	} {
		if _, err := s.CreateService(ctx, row); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := s.ListNodeServices(ctx, 1, a.ID)
	if err != nil || len(rows) != 3 {
		t.Fatalf("all sources/approval states: %v %v", rows, err)
	}
	for _, pair := range [][2]int64{{1, b.ID}, {2, a.ID}} {
		rows, err := s.ListNodeServices(ctx, core.MeshnetID(pair[0]), pair[1])
		if err != nil || len(rows) != 0 {
			t.Fatalf("tenant/device isolation: %v %v", rows, err)
		}
	}
	in.DeclaredServices = []core.Service{{Name: "admin", Proto: "tcp", Port: 9999}, {Name: "node", Proto: "tcp", Port: 9998}}
	if _, changed, err := c.RegisterWithChange(ctx, in); err != nil || !changed {
		t.Fatalf("changed declarations: %v %v", changed, err)
	}
	rows, err = s.ListNodeServices(ctx, 1, a.ID)
	if err != nil || len(rows) != 2 {
		t.Fatalf("withdraw pending: %v %v", rows, err)
	}
	for _, row := range rows {
		switch row.Name {
		case "admin":
			if row.Port != 80 || !row.Approved || !row.FromConsole() {
				t.Fatal("console declaration overwritten")
			}
		case "node":
			if row.Port != 9998 || row.Approved {
				t.Fatal("endpoint change kept approval")
			}
		}
	}
	in.DeclaredServices = nil
	if _, err := c.Register(ctx, in); err != nil {
		t.Fatal(err)
	}
	rows, _ = s.ListNodeServices(ctx, 1, a.ID)
	if len(rows) != 1 || !rows[0].FromConsole() {
		t.Fatal("device withdrawal removed console declaration")
	}
	rows, _ = s.ListNodeServices(ctx, 2, b.ID)
	if len(rows) != 1 || rows[0].Name != "foreign" {
		t.Fatal("other organization changed")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.ListNodeServices(canceled, 1, a.ID); err == nil {
		t.Fatal("canceled query succeeded")
	}
}
