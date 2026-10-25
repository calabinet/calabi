//go:build linux || darwin

package filecontrol

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
)

func shortSocketDirectory(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cfc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestUnixSocketAuthenticatesKernelUIDAndLease(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	path := filepath.Join(shortSocketDirectory(t), "control.sock")
	c := &Control{Source: Source{View: func() (Snapshot, error) { return Snapshot{Ready: true, Scope: "org7"}, nil }, Publish: func(context.Context, string, *meshpb.FileTransferInfo) error { return nil }}}
	c.owner = fmt.Sprintf("uid:%d", os.Geteuid())
	c.scope = "org7"
	c.lease = strings.Repeat("a", 64)
	c.expires = time.Now().Add(time.Minute)
	done, err := serveUnix(ctx, c, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); <-done }()
	v, err := callUnix(ctx, path, Request{Op: "snapshot", Lease: c.lease})
	if err != nil || !v.OwnsLease {
		t.Fatalf("kernel UID not authenticated: %+v %v", v, err)
	}
	v, err = callUnix(ctx, path, Request{Op: "snapshot", Lease: strings.Repeat("b", 64)})
	if err != nil || v.OwnsLease {
		t.Fatalf("wrong process secret got ownership: %+v %v", v, err)
	}
	if _, err := serveUnix(ctx, c, path); err == nil {
		t.Fatal("active listener replaced")
	}
}

func TestUnixSocketDoesNotRemoveOtherObjects(t *testing.T) {
	path := filepath.Join(shortSocketDirectory(t), "control.sock")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := serveUnix(context.Background(), nil, path); err == nil {
		t.Fatal("regular file replaced")
	}
	if b, _ := os.ReadFile(path); string(b) != "keep" {
		t.Fatal("unrelated object changed")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	l.SetUnlinkOnClose(false)
	l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done, err := serveUnix(ctx, &Control{}, path)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	<-done
}

func TestUnixEndpointSeparatesConsolePorts(t *testing.T) {
	a, err := socketPath("http://127.0.0.1:7400", 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := socketPath("http://127.0.0.1:7401", 0)
	if err != nil || a == b {
		t.Fatal("console ports share IPC")
	}
	if _, err := socketPath("http://example.com:7400", 0); err == nil {
		t.Fatal("nonlocal console accepted")
	}
}
