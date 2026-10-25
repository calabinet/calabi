package filecontrol

import (
	"context"
	"errors"
	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	"github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"strings"
	"testing"
	"time"
)

func TestOwnerLeaseCannotBeReplacedByAnotherUser(t *testing.T) {
	id, err := filetransfer.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	key := meshproto.NodeKey{1}
	info, err := id.Declaration(key, 17401, true)
	if err != nil {
		t.Fatal(err)
	}
	scope := "org7/session1"
	calls := 0
	c := &Control{Source: Source{View: func() (Snapshot, error) { return Snapshot{Ready: true, Scope: scope, NodeKey: key.String()}, nil }, Publish: func(context.Context, string, *meshpb.FileTransferInfo) error { calls++; return nil }}}
	request := Request{Op: "publish", Scope: scope, Lease: strings.Repeat("a", 64), Info: info}
	call := func(user string, req Request) Response { return c.Handle(context.Background(), user, req) }
	if got := call("userA", request); got.Error != "" {
		t.Fatal(got.Error)
	}
	if got := call("userB", request); got.Error == "" {
		t.Fatal("another user replaced the listener")
	}
	other := request
	other.Lease = strings.Repeat("b", 64)
	if got := call("userA", other); got.Error == "" {
		t.Fatal("another process replaced an active lease")
	}
	if calls != 1 {
		t.Fatal("denied requests reached coordinator")
	}
	if got := call("userA", Request{Op: "snapshot"}); got.Error != "" {
		t.Fatal(got.Error)
	}
	other = request
	other.Info = nil
	if got := call("userB", other); got.Error == "" {
		t.Fatal("another user withdrew the listener")
	}
	if got := call("userA", other); got.Error != "" {
		t.Fatal(got.Error)
	}
	if got := call("userB", request); got.Error != "" {
		t.Fatal(got.Error)
	}
	c.expires = time.Now().Add(-time.Second)
	if got := call("userA", request); got.Error != "" {
		t.Fatal("expired owner held the slot", got.Error)
	}
	scope = "org8/session2"
	if got := call("userA", request); got.Error == "" {
		t.Fatal("old scope published into new organization")
	}
	request.Scope = scope
	if got := call("userB", request); got.Error != "" {
		t.Fatal(got.Error)
	}
}

func TestLostCoordinatorResponseRetainsLocalOwner(t *testing.T) {
	id, _ := filetransfer.NewIdentity()
	key := meshproto.NodeKey{1}
	info, _ := id.Declaration(key, 17401, true)
	calls := 0
	c := &Control{Source: Source{View: func() (Snapshot, error) { return Snapshot{Ready: true, Scope: "one", NodeKey: key.String()}, nil }, Publish: func(context.Context, string, *meshpb.FileTransferInfo) error {
		calls++
		return errors.New("response lost")
	}}}
	req := Request{Op: "publish", Scope: "one", Lease: strings.Repeat("a", 64), Info: info}
	if c.Handle(context.Background(), "userA", req).Error == "" {
		t.Fatal("failed RPC appeared successful")
	}
	if c.Handle(context.Background(), "userB", req).Error == "" || calls != 1 {
		t.Fatal("uncertain publication unlocked active ownership")
	}
}

func TestMetadataEndpointBindsExactConsole(t *testing.T) {
	a, err := EndpointForConsole("http://127.0.0.1:7400")
	if err != nil {
		t.Fatal(err)
	}
	b, err := EndpointForConsole("http://127.0.0.1:7401")
	if err != nil || a == b {
		t.Fatal("daemon instances share metadata IPC")
	}
	for _, raw := range []string{"http://example.test:7400", "http://localhost:7400", "http://user@127.0.0.1:7400", "http://127.0.0.1:0", "http://127.0.0.1:7400/other", "http://127.0.0.1:7400?target=x"} {
		if _, err := EndpointForConsole(raw); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}

func TestReceptionFirewallFollowsAuthenticatedLease(t *testing.T) {
	id, _ := filetransfer.NewIdentity()
	key := meshproto.NodeKey{1}
	info, _ := id.Declaration(key, 17401, true)
	scope := "org/session1"
	ready := true
	var states []bool
	blocked := false
	publications := 0
	c := &Control{Source: Source{
		View: func() (Snapshot, error) { return Snapshot{Ready: ready, Scope: scope, NodeKey: key.String()}, nil },
		Receiving: func(_ context.Context, on bool) error {
			if blocked {
				return errors.New("host firewall refused")
			}
			states = append(states, on)
			return nil
		},
		Publish: func(context.Context, string, *meshpb.FileTransferInfo) error { publications++; return nil },
	}}
	ctx := context.Background()
	if err := c.StopReception(ctx); err != nil {
		t.Fatal(err)
	}
	req := Request{Op: "publish", Scope: scope, Lease: strings.Repeat("a", 64), Info: info}
	if got := c.Handle(ctx, "userA", req); got.Error != "" {
		t.Fatal(got.Error)
	}
	if got := c.Handle(ctx, "userB", req); got.Error == "" {
		t.Fatal("unauthorized user changed reception")
	}
	bad := req
	bad.Lease = strings.Repeat("b", 64)
	if got := c.Handle(ctx, "userA", bad); got.Error == "" {
		t.Fatal("wrong lease changed reception")
	}
	if len(states) != 2 || states[0] || !states[1] {
		t.Fatalf("unauthorized requests reached host firewall: %v", states)
	}
	c.expires = time.Now().Add(-time.Second)
	if err := c.ReconcileReception(ctx); err != nil || c.receiving {
		t.Fatalf("expired lease left reception enabled: %v", err)
	}
	if got := c.Handle(ctx, "userA", req); got.Error != "" {
		t.Fatal(got.Error)
	}
	scope = "org/session2"
	if err := c.ReconcileReception(ctx); err != nil || c.receiving {
		t.Fatalf("old mesh scope left reception enabled: %v", err)
	}
	req.Scope = scope
	if got := c.Handle(ctx, "userA", req); got.Error != "" {
		t.Fatal(got.Error)
	}
	ready = false
	if err := c.ReconcileReception(ctx); err != nil || c.receiving {
		t.Fatalf("disconnected mesh left reception enabled: %v", err)
	}
	ready = true
	blocked = true
	before := publications
	if got := c.Handle(ctx, "userA", req); got.Error == "" {
		t.Fatal("firewall failure was hidden")
	}
	if publications != before {
		t.Fatal("advertised reception despite firewall failure")
	}
	blocked = false
	if got := c.Handle(ctx, "userA", req); got.Error != "" {
		t.Fatal(got.Error)
	}
	req.Info, _ = id.Declaration(key, 17401, false)
	if got := c.Handle(ctx, "userA", req); got.Error != "" || c.receiving {
		t.Fatalf("receive off failed: %s", got.Error)
	}
	if states[len(states)-1] {
		t.Fatal("closed reception left firewall enabled")
	}
}
