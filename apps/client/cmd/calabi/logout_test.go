// logout_test.go — `calabi logout` has to reach the process that holds the session.
//
// Deleting the tokens from creds.json is only part of logging out. The daemon
// holds a LIVE edge session and its control loop blocks on a socket read no
// context cancels, so wiping the file underneath it leaves tunnels forwarding,
// presence reporting "online" and the mesh enrolled — under a session that no
// longer exists anywhere else. It notices at its next reconnect, which may be
// hours away, or never while the link stays up.
//
// So logout goes through the daemon's own endpoint (the one the SPA's 退出登录
// button uses), which tears all of that down. These pin the wire contract of
// that call.
//
// RUN: go test./apps/client/cmd/calabi/ -run TestLogout -v
package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/calabinet/calabi/apps/client/internal/creds"
)

// fakeDaemonConsole stands in for the daemon's :7400 API.
type fakeDaemonConsole struct {
	*httptest.Server
	status atomic.Int32
	path   atomic.Value // string
	token  atomic.Value // string
	hits   atomic.Int32
}

func newFakeDaemonConsole(t *testing.T, status int) *fakeDaemonConsole {
	t.Helper()
	d := &fakeDaemonConsole{}
	d.status.Store(int32(status))
	d.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.hits.Add(1)
		d.path.Store(r.URL.Path)
		d.token.Store(r.Header.Get("X-Local-Token"))
		code := int(d.status.Load())
		w.WriteHeader(code)
		if code == http.StatusForbidden {
			_, _ = w.Write([]byte(`{"error":"this client runs as a pinned API-key agent"}`))
		}
	}))
	t.Cleanup(d.Close)
	return d
}

// localTokenIn mints a local token in an isolated data dir and returns it.
func localTokenIn(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("CALABI_CONFIG", filepath.Join(dir, "config.json"))
	t.Setenv("CALABI_LOCAL_TOKEN", filepath.Join(dir, "local_token"))
	tok, err := creds.MintLocalToken()
	if err != nil {
		t.Fatalf("mint local token: %v", err)
	}
	return tok
}

// The daemon's write endpoints are gated on the local token; without the header
// the call 401s and logout would silently fall back to the file-only path,
// leaving the session up while printing "logged out".
func TestLogoutViaDaemonSendsTheLocalToken(t *testing.T) {
	want := localTokenIn(t)
	d := newFakeDaemonConsole(t, http.StatusOK)

	if err := logoutViaDaemon(context.Background(), strings.TrimPrefix(d.URL, "http://")); err != nil {
		t.Fatalf("logoutViaDaemon: %v", err)
	}
	if got, _ := d.path.Load().(string); got != "/v1/auth/logout" {
		t.Fatalf("posted to %q, want /v1/auth/logout", got)
	}
	if got, _ := d.token.Load().(string); got != want {
		t.Fatalf("X-Local-Token = %q, want the minted token", got)
	}
}

// A pinned API-key agent answers 403: it has no login session to end, and its
// credential lives in the service environment rather than this creds file. That
// must surface as an error so the caller falls back and says so, not as a
// success that claims something happened.
func TestLogoutViaDaemonReportsAnAgentRefusal(t *testing.T) {
	localTokenIn(t)
	d := newFakeDaemonConsole(t, http.StatusForbidden)

	err := logoutViaDaemon(context.Background(), strings.TrimPrefix(d.URL, "http://"))
	if err == nil {
		t.Fatal("a 403 was reported as success")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("error should carry the status so the fallback message can explain: %v", err)
	}
}

// No daemon listening: an error, never a silent success.
func TestLogoutViaDaemonUnreachableIsAnError(t *testing.T) {
	localTokenIn(t)
	// Port 1 on loopback: nothing serves it, and the connection is refused fast.
	if err := logoutViaDaemon(context.Background(), "127.0.0.1:1"); err == nil {
		t.Fatal("an unreachable daemon was reported as a successful logout")
	}
}

// --- the login half -------------------------------------------------------
//
// `calabi login` has the same gap in reverse: it writes the new token to the
// file, and the daemon keeps serving the PREVIOUS account until its session
// happens to drop. It cannot fix that by posting the sign-in through the
// daemon's /v1/auth/login — that endpoint pins the token to the personal org
// (prefer_personal_org), which `calabi login` deliberately does not do — so it
// signs in as always and then tells the daemon to re-read.

func TestRebindDaemonSendsTheLocalToken(t *testing.T) {
	want := localTokenIn(t)
	d := newFakeDaemonConsole(t, http.StatusOK)

	if err := rebindDaemon(context.Background(), strings.TrimPrefix(d.URL, "http://")); err != nil {
		t.Fatalf("rebindDaemon: %v", err)
	}
	if got, _ := d.path.Load().(string); got != "/v1/auth/rebind" {
		t.Fatalf("posted to %q, want /v1/auth/rebind", got)
	}
	if got, _ := d.token.Load().(string); got != want {
		t.Fatalf("X-Local-Token = %q, want the minted token", got)
	}
}

// A daemon older than the endpoint answers 404, a pinned agent 403. Both must
// surface so login can say the daemon did NOT switch, rather than claim it did.
func TestRebindDaemonReportsARefusal(t *testing.T) {
	localTokenIn(t)
	d := newFakeDaemonConsole(t, http.StatusForbidden)
	if err := rebindDaemon(context.Background(), strings.TrimPrefix(d.URL, "http://")); err == nil {
		t.Fatal("a 403 was reported as a successful rebind")
	}
}

// THE COST RULE. Rebinding restarts the edge session and every tunnel on it
// reconnects, so a re-login as the same account on a healthy daemon must NOT
// trigger one — that is the common case (a token expired in a shell), and
// charging it an outage would make `calabi login` something people avoid.
func TestNeedsRebindOnlyWhenItChangesSomething(t *testing.T) {
	for _, tc := range []struct {
		name            string
		prev, next      int64
		connected, want bool
	}{
		{"same account, daemon connected", 42, 42, true, false},
		// Same account but down: an expired or rejected credential looks exactly
		// like this from outside, and is what the login just fixed.
		{"same account, daemon not connected", 42, 42, false, true},
		{"different account, connected", 42, 77, true, true},
		{"different account, not connected", 42, 77, false, true},
		// Nothing was logged in before: there is no previous account to be
		// serving, so the only question is whether it is up.
		{"first login, daemon connected", 0, 42, true, false},
		{"first login, daemon not connected", 0, 42, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := needsRebind(tc.prev, tc.next, tc.connected); got != tc.want {
				t.Fatalf("needsRebind(%d, %d, connected=%v) = %v, want %v",
					tc.prev, tc.next, tc.connected, got, tc.want)
			}
		})
	}
}

// A daemon that cannot be reached, or answers something unparseable, counts as
// not connected: erring toward a rebind costs a reconnect, erring the other way
// leaves the machine serving the wrong account.
func TestDaemonConnectedFailsTowardRebinding(t *testing.T) {
	if daemonConnected(context.Background(), "127.0.0.1:1") {
		t.Fatal("an unreachable daemon reported as connected")
	}
	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok")) // the pre-JSON healthz an old daemon serves
	}))
	defer garbage.Close()
	if daemonConnected(context.Background(), strings.TrimPrefix(garbage.URL, "http://")) {
		t.Fatal("a non-JSON healthz reported as connected")
	}
}

// --- console.url is a pointer, not a fact ---------------------------------
//
// Reported 2026-09-15: login announced "your daemon is already running at
// http://127.0.0.1:7402", failed to hand the session over (nothing listening),
// and then blamed :7400 for being taken — three sentences about a port nobody
// served. The file had been written by an earlier run; the live daemon's bind
// took longer than the two seconds anyone waited for it, so it never overwrote
// the file. An address we have not confirmed must not be repeated as fact.

func TestLiveConsoleAddrRejectsAnAddressNothingAnswers(t *testing.T) {
	dir := t.TempDir()
	// A published URL pointing at a port nothing serves — exactly the stale
	// file on the reporter's machine.
	if err := os.WriteFile(filepath.Join(dir, consoleURLFile), []byte("http://127.0.0.1:1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := liveConsoleAddr(context.Background(), dir); got != "" {
		t.Fatalf("liveConsoleAddr = %q, want \"\" — nothing is serving there, and "+
			"naming it sends every later message to a dead port", got)
	}
}

func TestLiveConsoleAddrAcceptsOneThatAnswers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"state":"connected","connected":true}`))
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, consoleURLFile), []byte(srv.URL+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := liveConsoleAddr(context.Background(), dir); got != addr {
		t.Fatalf("liveConsoleAddr = %q, want %q", got, addr)
	}
}

// No file at all is the same answer as a dead one, and must not fall back to
// the default :7400 — on a multi-client machine that port belongs to whichever
// instance got there first, and handing it a rebind would be aimed at the wrong
// daemon entirely.
func TestLiveConsoleAddrWithNoPublishedURLDoesNotGuess(t *testing.T) {
	if got := liveConsoleAddr(context.Background(), t.TempDir()); got != "" {
		t.Fatalf("liveConsoleAddr = %q, want \"\" — guessing :7400 aims at whoever "+
			"holds it, which on a multi-client machine is somebody else", got)
	}
}
