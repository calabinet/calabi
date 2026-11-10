package filecontrol

import (
	"context"
	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	"github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"strings"
	"testing"
)

func TestClipboardOnlyListenerFirewallLease(t *testing.T) {
	id, e := filetransfer.NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	key := meshproto.NodeKey{1}
	info, e := id.DesktopDeclaration(key, 17401, false, false)
	if e != nil {
		t.Fatal(e)
	}
	var states []bool
	c := &Control{Source: Source{View: func() (Snapshot, error) { return Snapshot{Ready: true, Scope: "scope", NodeKey: key.String()}, nil },
		Receiving: func(_ context.Context, on bool) error { states = append(states, on); return nil },
		Publish: func(_ context.Context, _ string, info *meshpb.FileTransferInfo) error {
			if info != nil && (info.Receiving || len(info.AssistanceProof) > 0) {
				t.Fatal("clipboard enabled ordinary reception or assistance")
			}
			return nil
		}}}
	req := Request{Op: "publish", Scope: "scope", Lease: strings.Repeat("a", 64), Info: info, ClipboardListening: true}
	if got := c.Handle(context.Background(), "user", req); got.Error != "" {
		t.Fatal(got.Error)
	}
	if len(states) != 1 || !states[0] {
		t.Fatalf("clipboard-only listener not enabled: %v", states)
	}
	if got := c.Handle(context.Background(), "other-user", req); got.Error == "" {
		t.Fatal("other principal renewed listener")
	}
	if got := c.Handle(context.Background(), "user", req); got.Error != "" {
		t.Fatal(got.Error)
	}
	if len(states) != 1 {
		t.Fatal("renewal reconfigured firewall")
	}
	req.ClipboardListening = false
	if got := c.Handle(context.Background(), "user", req); got.Error != "" {
		t.Fatal(got.Error)
	}
	if len(states) != 2 || states[1] {
		t.Fatalf("closing clipboard left rule enabled: %v", states)
	}
	req.ClipboardListening = true
	req.Info = nil
	if got := c.Handle(context.Background(), "user", req); got.Error != "" {
		t.Fatal(got.Error)
	}
	if c.receiving {
		t.Fatal("clipboard flag without signed declaration enabled rule")
	}
}
