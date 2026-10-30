package core

import (
	"context"
	"errors"
	"testing"
)

type touchStore struct {
	*MemNodeStore
	touches, writes        int
	fail, disable, signOut bool
}

func (s *touchStore) Upsert(ctx context.Context, n *Node) (*Node, error) {
	s.writes++
	return s.MemNodeStore.Upsert(ctx, n)
}
func (s *touchStore) TouchRegistration(ctx context.Context, n *Node) (*Node, error) {
	s.touches++
	if s.fail {
		return nil, errors.New("touch failed")
	}
	if s.disable {
		_ = s.SetDisabled(ctx, n.ID, true)
	}
	if s.signOut {
		_ = s.SetSignedOut(ctx, n.ID, true)
	}
	return s.Get(ctx, n.ID)
}

func TestUnchangedRegistrationTouchPreservesChecks(t *testing.T) {
	ctx := context.Background()
	s := &touchStore{MemNodeStore: NewMemNodeStore()}
	c := newTestCoord()
	c.Nodes = s
	c.Services = NewMemServiceStore()
	in := RegisterInput{Meshnet: 1, NodeKey: key(1), Name: "client"}
	if _, err := c.Register(ctx, in); err != nil {
		t.Fatal(err)
	}
	in.Reauth = true
	if _, changed, err := c.RegisterWithChange(ctx, in); err != nil || changed || s.touches != 1 || s.writes != 1 {
		t.Fatalf("unchanged: %v %v %d %d", changed, err, s.touches, s.writes)
	}
	in.DeclaredServices = []Service{{Name: "db", Proto: "tcp", Port: 5432}}
	if _, changed, err := c.RegisterWithChange(ctx, in); err != nil || !changed || s.touches != 2 {
		t.Fatalf("declaration lost: %v %v", changed, err)
	}
	for _, change := range []func(){func() { in.Name = "new" }, func() { in.DiscoKey[0] = 9 }, func() { in.DeviceFingerprint = "new" }, func() { in.OS = "linux" }, func() { in.BlockIncoming = new(bool) }} {
		change()
		before := s.writes
		if _, changed, err := c.RegisterWithChange(ctx, in); err != nil || !changed || s.writes != before+1 {
			t.Fatalf("mutation bypassed write: %v %v", changed, err)
		}
	}
	s.fail = true
	writes := s.writes
	if _, _, err := c.RegisterWithChange(ctx, in); err == nil || s.writes != writes {
		t.Fatal("touch failure fell back to write")
	}
	s.fail = false
	s.disable = true
	if _, err := c.Register(ctx, in); !errors.Is(err, ErrNodeDisabled) {
		t.Fatalf("disabled during touch: %v", err)
	}
	s.disable = false
	_ = s.SetDisabled(ctx, 1, false)
	s.signOut = true
	if _, err := c.Register(ctx, in); !errors.Is(err, ErrNodeSignedOut) {
		t.Fatalf("signed out during touch: %v", err)
	}
}
