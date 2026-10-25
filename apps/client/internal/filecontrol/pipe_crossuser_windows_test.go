//go:build windows

package filecontrol

import (
	"context"
	"errors"
	winio "github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"sync"
	"testing"
	"time"
)

// Run the server and client tests under different OS users. Same-user tests
// exercise the owner's full-control ACE and cannot verify the desktop ACE.
func TestPipeCrossUserServer(t *testing.T) {
	path := os.Getenv("CALABI_TEST_PIPE_SERVER")
	if path == "" {
		t.Skip("requires a cross-user client")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	seen := make(chan struct{})
	var once sync.Once
	done, err := servePipe(ctx, path, &Control{Source: Source{View: func() (Snapshot, error) { once.Do(func() { close(seen) }); return Snapshot{Ready: true}, nil }}})
	if err != nil {
		t.Fatal(err)
	}
	t.Log("server ready")
	select {
	case <-seen:
		time.Sleep(100 * time.Millisecond)
		cancel()
	case <-ctx.Done():
		t.Error("no cross-user request received")
	}
	<-done
}

func TestPipeCrossUserClient(t *testing.T) {
	path := os.Getenv("CALABI_TEST_PIPE_CLIENT")
	if path == "" {
		t.Skip("requires a server owned by a different OS user")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := winio.DialPipeAccess(ctx, path, pipeAccess)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Generic write includes FILE_CREATE_PIPE_INSTANCE and must remain denied.
	other, err := winio.DialPipeContext(ctx, path)
	if other != nil {
		other.Close()
	}
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("generic access must be denied: %v", err)
	}
	h, err := pipeHandle(c)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("owner:", sd.String())
	// The server must resolve this process's actual SID and return a response.
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = c.Write([]byte("{\"op\":\"snapshot\"}\n")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4096)
	n, err := c.Read(b)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("no authenticated response")
	}
	t.Log(string(b[:n]))
}
