// logout_report_test.go — what `calabi logout` SAYS it did has to be true.
//
// It used to finish with "logged out" whatever had happened. Reproduced
// 2026-09-16 in a sandbox, three ways that was false:
//
//   - the daemon of this data dir ran on an API key: it refused, stayed online as
//     the key, and the CLI still printed "logged out" and "keeps its current
//     session until it reconnects" — it reconnects with the same key, forever;
//   - the client that mattered was an installed service, whose data dir a shell
//     cannot read: the CLI never saw it and said nothing, so on a desktop install
//     "logged out" sat next to an app that was still signed in;
//   - there was nothing to log out of, and it wrote an empty creds file anyway.
//
// RUN: go test./apps/client/cmd/calabi/ -run 'TestLogout|TestDaemonRefusal' -v
package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/calabi/calabi/apps/client/internal/creds"
)

// logoutSandbox gives logout its own data dir and local token, a control plane
// that refuses connections, and no API key in the environment.
func logoutSandbox(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	creds.SetDataDir(dir)
	t.Cleanup(func() { creds.SetDataDir("") })
	t.Setenv("CALABI_CONFIG", filepath.Join(dir, "config.json"))
	t.Setenv("CALABI_LOCAL_TOKEN", filepath.Join(dir, "local_token"))
	t.Setenv("CALABI_BFF_CONSOLE", "http://127.0.0.1:1")
	t.Setenv("CALABI_API_KEY", "")
	t.Setenv("CALABI_TOKEN", "")
	if _, err := creds.MintLocalToken(); err != nil {
		t.Fatalf("mint local token: %v", err)
	}
	return dir
}

// publishConsole writes the console.url a daemon of this data dir leaves behind.
func publishConsole(t *testing.T, dir, url string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, consoleURLFile), []byte(url+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func saveSignIn(t *testing.T) {
	t.Helper()
	c := &creds.Config{AccessToken: "access-example", RefreshToken: "refresh-example"}
	c.User.ID = 42
	c.User.Email = "dev@example.com"
	if err := creds.Save(c); err != nil {
		t.Fatalf("save creds: %v", err)
	}
}

func runLogoutCaptured(t *testing.T, daemonUp bool, others []string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := logout(context.Background(), &out, &out, daemonUp, others)
	return code, out.String()
}

// serviceModeConsole is another client's console: it answers /v1/service-mode.
func serviceModeConsole(t *testing.T, agent bool) string {
	t.Helper()
	body := `{"mode":"interactive","agent":false}`
	if agent {
		body = `{"mode":"agent","agent":true}`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/service-mode" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

// An agent daemon refuses the logout and stays online as its key. Nothing may
// read as a logout: not "logged out", not "until it reconnects", and not exit 0.
func TestLogoutAgentDaemonIsNotReportedAsLoggedOut(t *testing.T) {
	dir := logoutSandbox(t)
	d := newFakeDaemonConsole(t, http.StatusForbidden)
	publishConsole(t, dir, d.URL)

	code, out := runLogoutCaptured(t, true, nil)
	if code == 0 {
		t.Errorf("exit 0 for a logout that left the daemon online:\n%s", out)
	}
	for _, lie := range []string{"logged out", "reconnects"} {
		if strings.Contains(out, lie) {
			t.Errorf("output says %q, but the agent daemon is still running on its key:\n%s", lie, out)
		}
	}
	if !strings.Contains(out, "runs on an API key") {
		t.Errorf("output does not say what the daemon runs on:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.json")); !os.IsNotExist(err) {
		t.Errorf("wrote a creds file with nothing in it (stat err = %v)", err)
	}
}

// A sign-in saved next to an agent daemon is still worth clearing — a foreground
// daemon would prefer it to its key on the next reconnect — and saying exactly
// that much is fine. The daemon part must still not read as a logout.
func TestLogoutAgentDaemonStillClearsASavedSignIn(t *testing.T) {
	dir := logoutSandbox(t)
	saveSignIn(t)
	d := newFakeDaemonConsole(t, http.StatusForbidden)
	publishConsole(t, dir, d.URL)

	code, out := runLogoutCaptured(t, true, nil)
	if code == 0 {
		t.Errorf("exit 0 while the agent daemon stays online:\n%s", out)
	}
	if !strings.Contains(out, "cleared the sign-in saved for this client") {
		t.Errorf("output does not report the cleared sign-in:\n%s", out)
	}
	if strings.Contains(out, "logged out") {
		t.Errorf("output says \"logged out\" next to a daemon that is still online:\n%s", out)
	}
	c, err := creds.Load()
	if err != nil || c.AccessToken != "" || c.RefreshToken != "" {
		t.Fatalf("saved sign-in not cleared: access=%q refresh=%q err=%v", c.AccessToken, c.RefreshToken, err)
	}
}

// Nothing saved and no daemon: say so, and do not create a file to hold nothing.
func TestLogoutWithNothingSavedSaysSo(t *testing.T) {
	dir := logoutSandbox(t)

	code, out := runLogoutCaptured(t, false, nil)
	if code != 0 {
		t.Errorf("exit %d, want 0 — being logged out already is not an error", code)
	}
	if !strings.Contains(out, "not logged in") || strings.Contains(out, "logged out") {
		t.Errorf("output should say there was nothing to log out of:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.json")); !os.IsNotExist(err) {
		t.Errorf("wrote a creds file with nothing in it (stat err = %v)", err)
	}
}

// The plain case is unchanged: a saved sign-in, no daemon → cleared, exit 0.
func TestLogoutClearsASavedSignIn(t *testing.T) {
	logoutSandbox(t)
	saveSignIn(t)

	code, out := runLogoutCaptured(t, false, nil)
	if code != 0 || !strings.Contains(out, "logged out (local creds cleared)") {
		t.Fatalf("exit %d, output:\n%s", code, out)
	}
	c, _ := creds.Load()
	if c.AccessToken != "" || c.RefreshToken != "" {
		t.Fatal("saved sign-in not cleared")
	}
	if c.User.Email != "dev@example.com" {
		t.Errorf("email dropped (%q) — it pre-fills the next login", c.User.Email)
	}
}

// A key in this shell's environment outlives any logout: resolveCredential
// reads it ahead of the file. Say so.
func TestLogoutNamesAKeyLeftInTheEnvironment(t *testing.T) {
	logoutSandbox(t)
	saveSignIn(t)
	t.Setenv("CALABI_API_KEY", "tk_example")

	_, out := runLogoutCaptured(t, false, nil)
	if !strings.Contains(out, "CALABI_API_KEY is still set") {
		t.Fatalf("output does not mention the key still in the environment:\n%s", out)
	}
}

// The desktop installers' service keeps its data where a shell cannot read it,
// so the only sign of it is its console. Name every client that answers, say
// what it runs on, and ignore anything that is not a calabi console.
func TestLogoutNamesOtherClientsItDidNotTouch(t *testing.T) {
	logoutSandbox(t)
	signedIn := serviceModeConsole(t, false)
	agent := serviceModeConsole(t, true)
	notCalabi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer notCalabi.Close()

	_, out := runLogoutCaptured(t, false, []string{
		signedIn, agent, strings.TrimPrefix(notCalabi.URL, "http://"), "127.0.0.1:1",
	})
	if !strings.Contains(out, "(http://"+signedIn+") keeps its own") || !strings.Contains(out, "did not sign it out") {
		t.Errorf("the signed-in client at %s is not named as untouched:\n%s", signedIn, out)
	}
	if !strings.Contains(out, "(http://"+agent+") runs on its own") {
		t.Errorf("the agent at %s is not named as running on its key:\n%s", agent, out)
	}
	if n := strings.Count(out, "another calabi client"); n != 2 {
		t.Errorf("named %d other clients, want 2 (a non-calabi server and a dead port are not clients):\n%s", n, out)
	}
}

// This data dir's own daemon answers service-mode too, usually on the very
// address the default candidate names. Signing it out and then calling it
// "another client" that was not signed out would contradict the line above.
func TestLogoutDoesNotCallItsOwnDaemonAnotherClient(t *testing.T) {
	dir := logoutSandbox(t)
	own := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/service-mode":
			_, _ = w.Write([]byte(`{"mode":"interactive","agent":false}`))
		default:
			_, _ = w.Write([]byte(`{"status":"logged_out"}`))
		}
	}))
	defer own.Close()
	publishConsole(t, dir, own.URL)

	code, out := runLogoutCaptured(t, true, []string{strings.TrimPrefix(own.URL, "http://")})
	if code != 0 || !strings.Contains(out, "the daemon dropped its edge session") {
		t.Fatalf("exit %d, output:\n%s", code, out)
	}
	if strings.Contains(out, "another calabi client") {
		t.Errorf("its own daemon was reported as another client:\n%s", out)
	}
}

// The refusal is printed for a person: the daemon's sentence, not its JSON.
func TestDaemonRefusalPrintsTheDaemonsSentence(t *testing.T) {
	localTokenIn(t)
	d := newFakeDaemonConsole(t, http.StatusForbidden)
	err := logoutViaDaemon(context.Background(), strings.TrimPrefix(d.URL, "http://"))
	if err == nil || !isAgentRefusal(err) {
		t.Fatalf("err = %v, want an agent refusal", err)
	}
	if msg := err.Error(); strings.Contains(msg, `{"error"`) || !strings.Contains(msg, "pinned API-key agent") {
		t.Fatalf("refusal = %q, want the daemon's sentence without the JSON envelope", msg)
	}
}
