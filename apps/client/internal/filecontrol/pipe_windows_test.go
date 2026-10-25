//go:build windows

package filecontrol

import (
	"context"
	"fmt"
	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	"github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"os"
	"os/user"
	"testing"
	"time"
)

func TestNamedPipeUsesKernelUserIdentity(t *testing.T) {
	path := fmt.Sprintf(`\\.\pipe\Calabi.FileControl.Test.%d.%d`, os.Getpid(), time.Now().UnixNano())
	id, _ := filetransfer.NewIdentity()
	key := meshproto.NodeKey{1}
	info, _ := id.Declaration(key, 17401, false)
	c := &Control{Source: Source{View: func() (Snapshot, error) { return Snapshot{Ready: true, Scope: "test", NodeKey: key.String()}, nil }, Publish: func(context.Context, string, *meshpb.FileTransferInfo) error { return nil }}}
	ctx, cancel := context.WithCancel(context.Background())
	done, err := servePipe(ctx, path, c)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer func() { cancel(); <-done }()
	if _, err := callPipe(ctx, path, Request{Op: "publish", Scope: "test", Lease: fmt.Sprintf("%064x", 1), Info: info}); err != nil {
		t.Fatal(err)
	}
	account, _ := user.Current()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.owner != account.Uid {
		t.Fatalf("owner=%q actual=%q", c.owner, account.Uid)
	}
}
