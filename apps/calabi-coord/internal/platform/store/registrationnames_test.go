package store

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
)

func TestRegistrationNamesReauthenticationSecurity(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	c := &core.Coordinator{Nodes: s, IPAM: core.NewMemIPAM(), Services: s}
	admin, err := c.Register(ctx, core.RegisterInput{Meshnet: 1, NodeKey: key(1), Name: "  PrIvIlEgEd\u2003"})
	if err != nil {
		t.Fatal(err)
	}
	in := core.RegisterInput{Meshnet: 1, NodeKey: key(2), Name: "client"}
	n, err := c.Register(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Register(ctx, core.RegisterInput{Meshnet: 2, NodeKey: key(3), Name: "foreign"}); err != nil {
		t.Fatal(err)
	}
	names, err := s.ListRegistrationNames(ctx, 1, n.ID)
	if err != nil || len(names) != 1 || core.NormalizeNodeName(names[0]) != "privileged" {
		t.Fatalf("scope: %v %v", names, err)
	}
	if err := s.SetDisabled(ctx, admin.ID, true); err != nil {
		t.Fatal(err)
	}
	in.Reauth = true
	in.Name = "privileged"
	n, err = c.Register(ctx, in)
	if err != nil || core.NormalizeNodeName(n.Name) == "privileged" {
		t.Fatalf("disabled peer name takeover: %+v %v", n, err)
	}
	// Compare the optional name projection with the complete validation path,
	// including normalized collisions, suffixes and changes to route state.
	full := &core.Coordinator{Nodes: fullRegistrationStore{s}, IPAM: core.NewMemIPAM()}
	for _, name := range []string{"PRIVILEGED", "foreign", "client"} {
		in.Name = name
		a, err := c.Register(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		b, err := full.Register(ctx, in)
		if err != nil || a.Name != b.Name {
			t.Fatalf("different name decision: %v %v %v", a, b, err)
		}
	}
	if err := s.UpdateName(ctx, n.ID, "pinned"); err != nil {
		t.Fatal(err)
	}
	in.Name = "privileged"
	n, err = c.Register(ctx, in)
	if err != nil || n.Name != "pinned" {
		t.Fatal("admin name overwritten", err)
	}
	in.AdvertisedRoutes = []netip.Prefix{netip.MustParsePrefix("192.168.6.0/24")}
	if _, err := c.Register(ctx, in); err != nil {
		t.Fatal(err)
	}
	in.AdvertisedRoutes = nil
	if _, err := c.Register(ctx, in); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSignedOut(ctx, n.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Register(ctx, in); !errors.Is(err, core.ErrNodeSignedOut) {
		t.Fatalf("signed-out node readmitted: %v", err)
	}
	if err := s.SetSignedOut(ctx, n.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDisabled(ctx, n.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Register(ctx, in); !errors.Is(err, core.ErrNodeDisabled) {
		t.Fatalf("disabled readmitted: %v", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.ListRegistrationNames(canceled, 1, n.ID); err == nil {
		t.Fatal("canceled query succeeded")
	}
	if err := s.Delete(ctx, n.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Register(ctx, in); !errors.Is(err, core.ErrNodeNotFound) {
		t.Fatalf("deleted node recreated: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Register(ctx, in); err == nil {
		t.Fatal("database failure admitted registration")
	}
}

func TestTouchRegistrationIdentityAndFreshAdminState(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	n, err := s.Upsert(ctx, &core.Node{Meshnet: 1, NodeKey: key(11), Name: "old"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateName(ctx, n.ID, "admin-name"); err != nil {
		t.Fatal(err)
	}
	got, err := s.TouchRegistration(ctx, n)
	if err != nil || got.Name != "admin-name" || !got.NamePinned || got.LastSeen.Before(n.LastSeen) {
		t.Fatalf("stale admin state: %+v %v", got, err)
	}
	wrong := *n
	wrong.Meshnet = 2
	if _, err := s.TouchRegistration(ctx, &wrong); !errors.Is(err, core.ErrNodeNotFound) {
		t.Fatalf("cross-org touch: %v", err)
	}
	wrong = *n
	wrong.NodeKey = key(12)
	if _, err := s.TouchRegistration(ctx, &wrong); !errors.Is(err, core.ErrNodeNotFound) {
		t.Fatalf("wrong-key touch: %v", err)
	}
	if err := s.SetSignedOut(ctx, n.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TouchRegistration(ctx, n); err == nil {
		t.Fatal("signed-out touch succeeded")
	}
	if err := s.SetSignedOut(ctx, n.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDisabled(ctx, n.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TouchRegistration(ctx, n); err == nil {
		t.Fatal("disabled touch succeeded")
	}
}
