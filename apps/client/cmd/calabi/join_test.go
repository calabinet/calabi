package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/calabinet/calabi/apps/client/internal/creds"
)

// `calabi join` with no daemon running joins here: the console's config names
// the coordinator, the mode is standalone, and the invite is spent once. A
// second join is refused until asked to replace, and spends nothing.
func TestJoinCommandWithoutADaemon(t *testing.T) {
	dir := isolateDataDir(t)
	coord := startFakeSHCoord(t, true, "invite-1")

	if code := runJoin([]string{"--no-start-daemon", "--name", "nas", coord.link("invite-1")}); code != 0 {
		t.Fatalf("join: exit %d", code)
	}
	cfg, err := loadLocalConfig(filepath.Join(dir, "tunnels.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if m := cfg.Mesh; m.Coord != coord.addr || m.Name != "nas" || !m.Enabled || len(m.Pins) != 1 || m.Pins[0] != coord.pin || m.AuthKey != "" {
		t.Fatalf("mesh block: %+v", m)
	}
	if c, _ := creds.Load(); c == nil || c.Mode != clientModeStandalone {
		t.Fatalf("mode: %+v", c)
	}
	if regs := coord.registrations(); strings.Join(regs, ",") != "key:invite-1" {
		t.Fatalf("registrations: %v", regs)
	}

	var code int
	msg := captureStderr(t, func() { code = runJoin([]string{"--no-start-daemon", coord.link("invite-1")}) })
	if code != 1 || !strings.Contains(msg, "--replace") {
		t.Fatalf("joining again: exit %d, %q; want a refusal naming --replace", code, msg)
	}
	if regs := coord.registrations(); len(regs) != 1 {
		t.Fatalf("a refused join spent the invite: %v", regs)
	}
}

// Signed in to calabi.net, the join is refused until the person signs out, and
// nothing is spent.
func TestJoinCommandWhileSignedIn(t *testing.T) {
	isolateDataDir(t)
	coord := startFakeSHCoord(t, true, "invite-1")
	signedIn(t, &creds.Config{})
	var code int
	msg := captureStderr(t, func() { code = runJoin([]string{"--no-start-daemon", coord.link("invite-1")}) })
	if code != 1 || !strings.Contains(msg, "calabi logout") {
		t.Fatalf("join while signed in: exit %d, %q", code, msg)
	}
	if regs := coord.registrations(); len(regs) != 0 {
		t.Fatalf("registrations: %v", regs)
	}
	if code := runJoin([]string{"--no-start-daemon", "not-an-invite"}); code != 2 {
		t.Fatalf("a bad link: exit %d, want 2", code)
	}
}

// A daemon of this user's data dir that predates the join endpoint: the message
// names that daemon (its console), because on a machine that already runs calabi
// it is that client — not the copy of calabi the join was typed with.
func TestJoinThroughATooOldDaemonNamesIt(t *testing.T) {
	old := httptest.NewServer(http.NotFoundHandler())
	defer old.Close()
	console := strings.TrimPrefix(old.URL, "http://")
	status, body := joinThroughDaemon(context.Background(), console, joinRequest{Mesh: &joinMesh{Link: "calabi://join?s=example.com%3A7012&k=ck_x&v=1"}})
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", status)
	}
	msg, _ := body["error"].(string)
	for _, want := range []string{"already running", old.URL, "too old", "stop it"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message does not say %q: %q", want, msg)
		}
	}
}
