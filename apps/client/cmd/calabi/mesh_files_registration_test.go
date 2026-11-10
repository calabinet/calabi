//go:build windows || darwin || linux

package main

import (
	"context"
	"github.com/calabinet/calabi/apps/client/internal/filecontrol"
	mp "github.com/calabinet/calabi/pkg/mesh-proto"
	"github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"sync/atomic"
	"testing"
)

func TestRepublishOnNewMeshRegistration(t *testing.T) {
	for _, key := range []string{"HOME", "APPDATA", "XDG_CONFIG_HOME", "LOCALAPPDATA"} {
		t.Setenv(key, t.TempDir())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var gen, uploads atomic.Int64
	gen.Store(1)
	ctl := &filecontrol.Control{Source: filecontrol.Source{
		View: func() (filecontrol.Snapshot, error) {
			return filecontrol.Snapshot{Ready: true, Registration: gen.Load(), Scope: "test", NodeKey: mp.NodeKey{1}.String(), Overlay: "127.0.0.1"}, nil
		},
		Publish: func(_ context.Context, _ string, info *meshpb.FileTransferInfo) error {
			if info != nil {
				uploads.Add(1)
			}
			return nil
		},
	}}
	const console = "http://127.0.0.1:17469"
	done, e := filecontrol.Serve(ctx, ctl, console)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { cancel(); <-done }()
	d, e := newDesktopFileAgent(ctx, console)
	if e != nil {
		t.Fatal(e)
	}
	defer d.close()
	if _, e = d.handle(fileAction{Action: "receiving", Enabled: true}); e != nil {
		t.Fatal(e)
	}
	before := uploads.Load()
	gen.Add(1)
	d.poll()
	d.poll()
	if got := uploads.Load() - before; got != 1 {
		t.Fatalf("new registration with retained local lease: got %d extra publications", got)
	}
}
