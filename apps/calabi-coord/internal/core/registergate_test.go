package core

import (
	"context"
	"errors"
	"testing"
	"time"
)

type failedRegistrationNames struct{ NodeStore }

func (s failedRegistrationNames) ListRegistrationNames(context.Context, MeshnetID, int64) ([]string, error) {
	return nil, errors.New("names unavailable")
}

func TestRegistrationNamesFailureDoesNotWrite(t *testing.T) {
	c := newTestCoord()
	ctx := context.Background()
	in := RegisterInput{Meshnet: 1, NodeKey: key(1), Name: "original"}
	n, err := c.Register(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	c.Nodes = failedRegistrationNames{c.Nodes}
	in.Name = "privileged"
	in.Reauth = true
	if _, err := c.Register(ctx, in); err == nil {
		t.Fatal("failed name read admitted mutation")
	}
	got, err := c.Nodes.Get(ctx, n.ID)
	if err != nil || got.Name != "original" {
		t.Fatal("failed validation wrote node", err)
	}
}

func TestRegistrationQueueCancellation(t *testing.T) {
	c := newTestCoord()
	unlock, err := c.lockMeshnet(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := c.Register(ctx, RegisterInput{Meshnet: 1, NodeKey: key(1), Name: "blocked"})
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled registration stayed queued")
	}
	if nodes, _ := c.Nodes.ListMeshnet(context.Background(), 1); len(nodes) != 0 {
		t.Fatal("canceled request wrote device")
	}
	// An unrelated organization is not behind this gate.
	if _, err := c.Register(context.Background(), RegisterInput{Meshnet: 2, NodeKey: key(2), Name: "other"}); err != nil {
		t.Fatal(err)
	}
}
