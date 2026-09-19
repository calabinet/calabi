package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// `calabi mesh down` and a bare `calabi mesh up` switch the running daemon's
// mesh, with the daemon's own local token. `mesh up` with flags is the
// foreground mesh, and must not be mistaken for the switch.
func TestMeshSwitchGoesToTheDaemon(t *testing.T) {
	isolateDataDir(t)
	var mu sync.Mutex
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/local-token" {
			_, _ = w.Write([]byte(`{"token":"daemon-token"}`))
			return
		}
		mu.Lock()
		got = append(got, r.Method+" "+r.URL.Path+" "+r.Header.Get("X-Local-Token"))
		mu.Unlock()
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()
	t.Setenv("CALABI_STATUS_ADDR", strings.TrimPrefix(srv.URL, "http://"))

	if code := runMeshDown(nil); code != 0 {
		t.Fatalf("mesh down: exit %d", code)
	}
	if code := runMeshUp(nil); code != 0 {
		t.Fatalf("mesh up: exit %d", code)
	}
	if code := runMeshUp([]string{"--coord", "coord.example.com:7012"}); code != 2 {
		t.Fatalf("mesh up with flags but no key: exit %d, want 2 (the foreground mesh's usage error)", code)
	}
	mu.Lock()
	defer mu.Unlock()
	want := "POST /v1/mesh/down daemon-token,POST /v1/mesh/up daemon-token"
	if strings.Join(got, ",") != want {
		t.Fatalf("requests %v, want %s", got, want)
	}
}
