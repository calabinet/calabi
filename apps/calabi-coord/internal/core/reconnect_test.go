package core

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

type failedRegistrationLookup struct{ NodeStore }

func (s failedRegistrationLookup) FindByKey(context.Context, MeshnetID, meshproto.NodeKey) (*Node, error) {
	return nil, errors.New("database unavailable")
}

type failedServiceRead struct{ ServiceStore }

func (s failedServiceRead) ListServices(context.Context, MeshnetID) ([]Service, error) {
	return nil, errors.New("services unavailable")
}

type partiallyFailedServiceDelete struct{ ServiceStore }

func (s partiallyFailedServiceDelete) DeleteService(ctx context.Context, id int64) error {
	if err := s.ServiceStore.DeleteService(ctx, id); err != nil {
		return err
	}
	return errors.New("write committed but response failed")
}

func TestReconnectPartialServiceFailureMustNotify(t *testing.T) {
	c := newTestCoord()
	c.Services = NewMemServiceStore()
	ctx := context.Background()
	in := RegisterInput{Meshnet: 1, Name: "laptop", NodeKey: key(1), DeclaredServices: []Service{{Name: "db", Proto: "tcp", Port: 5432}}}
	if _, err := c.Register(ctx, in); err != nil {
		t.Fatal(err)
	}
	c.Services = partiallyFailedServiceDelete{c.Services}
	in.DeclaredServices = nil
	if _, changed, err := c.RegisterWithChange(ctx, in); err != nil || !changed {
		t.Fatalf("partial withdrawal must notify: %v %v", changed, err)
	}
	services, err := c.Services.ListServices(ctx, 1)
	if err != nil || len(services) != 0 {
		t.Fatalf("fixture did not commit withdrawal: %v %v", services, err)
	}
}

func TestReconnectChangeDetection(t *testing.T) {
	ctx := context.Background()
	c := newTestCoord()
	c.Services = NewMemServiceStore()
	in := RegisterInput{Meshnet: 1, Name: "laptop", NodeKey: key(1)}
	n, changed, err := c.RegisterWithChange(ctx, in)
	if err != nil || !changed {
		t.Fatalf("new device: %v %v", changed, err)
	}
	if _, changed, err = c.RegisterWithChange(ctx, in); err != nil || changed {
		t.Fatalf("unchanged: %v %v", changed, err)
	}
	for _, mutate := range []func(*RegisterInput){
		func(p *RegisterInput) { p.Name = "renamed" },
		func(p *RegisterInput) { p.Tags = []string{"restricted"} },
		func(p *RegisterInput) { p.OwnerUserID = 42 },
		func(p *RegisterInput) { p.DiscoKey[0] = 7 },
		func(p *RegisterInput) { p.BlockIncoming = new(bool) },
		func(p *RegisterInput) { p.AdvertisedRoutes = []netip.Prefix{netip.MustParsePrefix("192.168.8.0/24")} },
		func(p *RegisterInput) { p.DeclaredServices = []Service{{Name: "db", Proto: "tcp", Port: 5432}} },
		func(p *RegisterInput) { p.DeclaredServices = nil },
	} {
		mutate(&in)
		if _, changed, err = c.RegisterWithChange(ctx, in); err != nil || !changed {
			t.Fatalf("changed input: %v %v", changed, err)
		}
		if _, changed, err = c.RegisterWithChange(ctx, in); err != nil || changed {
			t.Fatalf("settled input: %v %v", changed, err)
		}
	}
	c.Services = failedServiceRead{c.Services}
	if _, changed, err = c.RegisterWithChange(ctx, in); err != nil || !changed {
		t.Fatalf("uncertain service state must notify: %v %v", changed, err)
	}
	if err := c.Nodes.SetDisabled(ctx, n.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, _, err = c.RegisterWithChange(ctx, in); !errors.Is(err, ErrNodeDisabled) {
		t.Fatalf("disabled: %v", err)
	}
	if err := c.Nodes.SetDisabled(ctx, n.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := c.Nodes.SetSignedOut(ctx, n.ID, true); err != nil {
		t.Fatal(err)
	}
	in.Reauth = true
	if _, _, err = c.RegisterWithChange(ctx, in); !errors.Is(err, ErrNodeSignedOut) {
		t.Fatalf("signed out: %v", err)
	}
	if err := c.Nodes.Delete(ctx, n.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = c.RegisterWithChange(ctx, in); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("deleted: %v", err)
	}
}

func TestRegistrationLookupFailureDoesNotCreateDevice(t *testing.T) {
	c := newTestCoord()
	c.Nodes = failedRegistrationLookup{c.Nodes}
	if _, _, err := c.RegisterWithChange(context.Background(), RegisterInput{Meshnet: 1, Name: "a", NodeKey: key(1)}); err == nil {
		t.Fatal("lookup failure admitted device")
	}
	nodes, _ := c.Nodes.ListMeshnet(context.Background(), 1)
	if len(nodes) != 0 {
		t.Fatal("lookup failure created device")
	}
}
