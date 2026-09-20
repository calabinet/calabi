package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/creds"
	"github.com/calabinet/calabi/apps/client/internal/status"
)

// `calabi mesh status` used to assume 127.0.0.1:7400 and report a running
// daemon as unreachable whenever listenWithFallback had moved it (7400 busy →
// 7401 …). The daemon already writes its REAL bound URL to console.url; these
// pin that the CLI reads it, and in the right order.

func TestConsoleCandidatesPreferTheAddressTheDaemonRecorded(t *testing.T) {
	dir := t.TempDir()
	creds.SetDataDir(dir)
	t.Cleanup(func() { creds.SetDataDir("") })
	t.Setenv("CALABI_STATUS_ADDR", "")

	const recorded = "http://127.0.0.1:7403"
	if err := os.WriteFile(filepath.Join(dir, consoleURLFile), []byte(recorded+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := meshConsoleCandidates()
	if len(got) == 0 || got[0] != recorded {
		t.Fatalf("candidates = %v, want %q first", got, recorded)
	}
	// The default must still be in the list: console.url is never removed when a
	// daemon stops, so a stale entry must not become the only thing we try.
	if !containsStr(got, "http://"+defaultStatusAddr) {
		t.Errorf("candidates = %v, want the default %q as a fallback", got, defaultStatusAddr)
	}
}

func TestConsoleCandidatesFallBackToTheDefault(t *testing.T) {
	creds.SetDataDir(t.TempDir()) // empty: no console.url
	t.Cleanup(func() { creds.SetDataDir("") })
	t.Setenv("CALABI_STATUS_ADDR", "")

	got := meshConsoleCandidates()
	if len(got) == 0 || got[len(got)-1] != "http://"+defaultStatusAddr {
		t.Errorf("candidates = %v, want the default last", got)
	}
}

// An explicit address is the ONLY candidate. Falling through to another daemon
// after the user named one would answer a question they did not ask — on a
// machine running several clients, with different identities, that is a wrong
// answer rather than a missing one.
func TestExplicitStatusAddrIsTheOnlyCandidate(t *testing.T) {
	dir := t.TempDir()
	creds.SetDataDir(dir)
	t.Cleanup(func() { creds.SetDataDir("") })
	if err := os.WriteFile(filepath.Join(dir, consoleURLFile), []byte("http://127.0.0.1:7403\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CALABI_STATUS_ADDR", "127.0.0.1:9999")

	got := meshConsoleCandidates()
	if len(got) != 1 || got[0] != "http://127.0.0.1:9999" {
		t.Errorf("candidates = %v, want exactly [http://127.0.0.1:9999]", got)
	}
}

// Garbage in console.url must not become a candidate: a truncated or empty file
// would otherwise turn into a bare "http://" request and a confusing error.
func TestConsoleCandidatesIgnoreAnUnusableFile(t *testing.T) {
	dir := t.TempDir()
	creds.SetDataDir(dir)
	t.Cleanup(func() { creds.SetDataDir("") })
	t.Setenv("CALABI_STATUS_ADDR", "")

	for _, junk := range []string{"", "   \n", "not-a-url", "127.0.0.1:7401"} {
		if err := os.WriteFile(filepath.Join(dir, consoleURLFile), []byte(junk), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, c := range meshConsoleCandidates() {
			if !strings.HasPrefix(c, "http://") || c == "http://" {
				t.Errorf("console.url %q produced candidate %q", junk, c)
			}
		}
	}
}

// console.url says where this client's daemon is. A one-shot `calabi http`
// started beside it serves its own page on the next port, and used to write that
// page's address there — `calabi mesh up` then got a 404 from the one-shot, and
// `calabi join` would have posted the join to it. The daemon's console still
// writes it.
func TestOnlyTheDaemonConsoleRecordsItsAddress(t *testing.T) {
	dir := t.TempDir()
	creds.SetDataDir(dir)
	t.Cleanup(func() { creds.SetDataDir("") })
	file := filepath.Join(dir, consoleURLFile)

	addr := freeLoopbackAddr(t)
	t.Setenv("CALABI_STATUS_ADDR", addr)
	startStatusPage(quietTestLogger(), status.New("test", ""))
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the one-shot page never came up: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if b, err := os.ReadFile(file); err == nil {
		t.Fatalf("a one-shot page recorded itself as the console: %q", strings.TrimSpace(string(b)))
	}

	daemon := freeLoopbackAddr(t)
	t.Setenv("CALABI_STATUS_ADDR", daemon)
	ctx, cancel := context.WithCancel(context.Background())
	url, done := startDaemonConsole(ctx, quietTestLogger(), status.New("test", ""), func(*http.ServeMux) {})
	t.Cleanup(func() { cancel(); <-done })
	if got := readConsoleURLFile(file); got == "" || got != url {
		t.Fatalf("console.url = %q, want the daemon's %q", got, url)
	}
}

// freeLoopbackAddr is a loopback address nothing is listening on.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func containsStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
