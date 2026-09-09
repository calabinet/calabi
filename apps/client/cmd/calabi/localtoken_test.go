package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The token has to come from the DAEMON, not from whatever creds file this
// process can reach.
//
// The failure it fixes: on macOS the daemon is a system LaunchDaemon with its
// own creds directory, so a CLI reading its own copy presented a token the
// daemon had never minted and every gated endpoint answered
//
//	401 {"error":"local-token mismatch (fetch /v1/local-token)"}
//
// with the daemon plainly running and answering unauthenticated reads a line
// earlier. The error names the fix; nothing was doing it.
func TestLocalTokenComesFromTheDaemon(t *testing.T) {
	const want = "token-the-daemon-actually-minted"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/local-token" {
			t.Errorf("asked for %s, want /v1/local-token", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"token":"` + want + `"}`))
	}))
	defer srv.Close()

	if got := localTokenFor(srv.URL); got != want {
		t.Errorf("localTokenFor = %q, want the daemon's %q", got, want)
	}
}

// A daemon too old to serve the endpoint must not leave the CLI empty-handed —
// it falls back to the creds file, which is what every older install has.
func TestLocalTokenFallsBackWhenTheEndpointIsMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	// Whatever the creds file holds here (usually nothing in a test environment),
	// the point is that a 404 does not panic and does not return the 404 body as
	// if it were a token.
	if got := localTokenFor(srv.URL); got == "404 page not found\n" || len(got) > 200 {
		t.Errorf("a missing endpoint produced %q instead of falling back", got)
	}
}

// An unreachable daemon must not hang the CLI. The endpoint is on loopback, so a
// connection that does not answer promptly is not going to answer at all, and a
// diagnostic that blocks forever is worse than one that reports nothing.
func TestLocalTokenDoesNotHangOnADeadDaemon(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = localTokenFor("http://127.0.0.1:1") // nothing listens on port 1
	}()
	select {
	case <-done:
	case <-t.Context().Done():
		t.Fatal("localTokenFor hung against a dead daemon")
	}
}
