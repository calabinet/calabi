package filecontrol

import (
	"context"
	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
	mp "github.com/calabinet/calabi/pkg/mesh-proto"
	"github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"strings"
	"testing"
	"time"
)

func TestSnapshotDuringSlowRenewal(t *testing.T) {
	id, e := filetransfer.NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	key := mp.NodeKey{1}
	info, e := id.DesktopDeclaration(key, 17401, false, true)
	if e != nil {
		t.Fatal(e)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	calls := 0
	c := Control{Source: Source{View: func() (Snapshot, error) { return Snapshot{Scope: "org", Ready: true, NodeKey: key.String()}, nil }, Publish: func(context.Context, string, *meshpb.FileTransferInfo) error {
		calls++
		if calls == 2 {
			close(entered)
			<-release
		}
		return nil
	}}}
	req := Request{Op: "publish", Scope: "org", Lease: strings.Repeat("a", 64), Info: info}
	ctx := context.Background()
	if got := c.Handle(ctx, "user", req); got.Error != "" {
		t.Fatal(got.Error)
	}
	done := make(chan Response, 1)
	go func() { done <- c.Handle(ctx, "user", req) }()
	<-entered
	defer func() {
		close(release)
		if got := <-done; got.Error != "" {
			t.Error(got.Error)
		}
	}()
	snapshot := make(chan bool, 1)
	go func() {
		r := Request{Op: "snapshot", Lease: req.Lease}
		snapshot <- c.Handle(ctx, "user", r).Snapshot.OwnsLease && !c.Handle(ctx, "other", r).Snapshot.OwnsLease
	}()
	select {
	case ok := <-snapshot:
		if !ok {
			t.Fatal("wrong ownership")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("snapshot blocked by renewal")
	}
}
