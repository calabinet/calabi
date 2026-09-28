package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// consoleWithoutUpdates is a daemon console that serves no /v1/update* — the
// local daemon's shape (daemon_local.go → internal/localweb registers no such
// route, and status.handleIndex 404s everything else). me, when non-nil, answers
// GET /v1/me.
func consoleWithoutUpdates(t *testing.T, me http.HandlerFunc) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/me" && me != nil {
			me(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// What `calabi update` says on a daemon that has no /v1/update.
//
// A device joined to a self-hosted server runs the LOCAL daemon, which registers
// no /v1/update* and never builds an update agent. The old answer there was "a
// dev build, or updates are disabled": both false, and the second one implies a
// switch — while CALABI_UPDATE_MANIFEST is read inside newUpdateAgent, which that
// daemon never calls. Nothing the person could do, described as something they
// configured.
func TestUpdateOnASelfHostedDeviceSaysWhereItsVersionComesFrom(t *testing.T) {
	base := consoleWithoutUpdates(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"user":{"email":"standalone"},"plan":{"code":"standalone"}}`))
	})

	_, err := postUpdate(base, "/v1/update/check", "tok")
	if err == nil {
		t.Fatal("a daemon with no /v1/update answered without an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "self-hosted server") {
		t.Errorf("message does not say why this device has no self-update:\n%s", msg)
	}
	// The two claims that were wrong must be GONE, not merely joined by a third.
	if strings.Contains(msg, "dev build") || strings.Contains(msg, "disabled") {
		t.Errorf("still blaming a dev build / a disabled setting:\n%s", msg)
	}
	// And it has to leave the person with something to do.
	if !strings.Contains(msg, "version") {
		t.Errorf("message names no next step:\n%s", msg)
	}
}

// The control: the same 404 from a PLATFORM daemon keeps the old wording. This is
// the half that makes the test above mean anything — a change that always said
// "self-hosted" would pass that one and fail this one.
//
// Every way a platform daemon can answer /v1/me is covered, because they arrive
// differently and none of them may be read as standalone: 401 (nobody signed in,
// so it cannot answer), a real plan code, and a daemon too old to serve it.
func TestUpdateOnAPlatformDaemonKeepsTheDevBuildWording(t *testing.T) {
	for _, tc := range []struct {
		name string
		me   http.HandlerFunc
	}{
		{"not signed in", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":"not signed in"}`, http.StatusUnauthorized)
		}},
		{"signed in on a real plan", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"user":{"email":"a@b.c"},"plan":{"code":"pro"}}`))
		}},
		{"me not served at all", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := postUpdate(consoleWithoutUpdates(t, tc.me), "/v1/update/check", "tok")
			if err == nil {
				t.Fatal("a daemon with no /v1/update answered without an error")
			}
			if msg := err.Error(); !strings.Contains(msg, "dev build") {
				t.Errorf("a platform daemon was told it is self-hosted:\n%s", msg)
			}
		})
	}
}

// An unreachable console must not become a claim either: the probe is a SECOND
// request, and it can fail on its own after the first one got an answer.
func TestUpdateProbeFailureDoesNotClaimSelfHosted(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	base := srv.URL
	srv.Close() // nothing listens now

	if daemonIsSelfHosted(base) {
		t.Error("a console that does not answer was reported as self-hosted")
	}
}
