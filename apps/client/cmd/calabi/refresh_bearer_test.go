package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/creds"
)

// refreshServer stands in for bff-console's /v1/auth/refresh with identity-svc's
// real semantics: a refresh token is good for ONE exchange (it is rotated on use)
// and a replay is refused. during, when set, runs inside the exchange — the window
// in which the rest of the daemon may be writing creds.
func refreshServer(t *testing.T, current string, during func()) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/refresh" {
			http.NotFound(w, r)
			return
		}
		var in struct {
			RefreshToken string `json:"refresh_token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		if during != nil {
			during()
		}
		mu.Lock()
		defer mu.Unlock()
		if in.RefreshToken != current {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "session not found"})
			return
		}
		n++
		current = fmt.Sprintf("usr_r%d", n)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token":  fmt.Sprintf("jwt-%d", n),
			"refresh_token": current,
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func useRefreshCreds(t *testing.T, srv *httptest.Server, c *creds.Config) {
	t.Helper()
	t.Setenv("CALABI_CONFIG", filepath.Join(t.TempDir(), "creds.json"))
	t.Setenv("CALABI_BFF_CONSOLE", srv.URL)
	if err := creds.Save(c); err != nil {
		t.Fatal(err)
	}
}

// The exchange is a network round trip. Whatever the daemon persisted during it —
// here a region switch from the console — must survive the new token being saved.
func TestRefreshBearerKeepsWhatWasSavedDuringTheExchange(t *testing.T) {
	srv := refreshServer(t, "usr_r0", func() {
		c, _ := creds.Load()
		c.EdgeRegion = "sgp"
		_ = creds.Save(c)
	})
	useRefreshCreds(t, srv, &creds.Config{AccessToken: "jwt-0", RefreshToken: "usr_r0", EdgeRegion: "lax"})

	if got := refreshBearer(context.Background()); got != "jwt-1" {
		t.Fatalf("refreshBearer = %q, want jwt-1", got)
	}
	c, _ := creds.Load()
	if c.EdgeRegion != "sgp" {
		t.Fatalf("the region switch saved during the refresh was rolled back to %q", c.EdgeRegion)
	}
	if c.AccessToken != "jwt-1" || c.RefreshToken != "usr_r1" {
		t.Fatalf("tokens on disk = (%q, %q), want (jwt-1, usr_r1)", c.AccessToken, c.RefreshToken)
	}
}

// A sign-in or an org switch during the exchange replaces the session. What it
// wrote is newer than the token this exchange returns and must not be clobbered.
func TestRefreshBearerDoesNotClobberASessionReplacedMeanwhile(t *testing.T) {
	srv := refreshServer(t, "usr_r0", func() {
		c, _ := creds.Load()
		c.AccessToken, c.RefreshToken = "jwt-other-org", "usr_other"
		_ = creds.Save(c)
	})
	useRefreshCreds(t, srv, &creds.Config{AccessToken: "jwt-0", RefreshToken: "usr_r0"})

	got := refreshBearer(context.Background())
	c, _ := creds.Load()
	if c.AccessToken != "jwt-other-org" || c.RefreshToken != "usr_other" {
		t.Fatalf("the session that replaced ours was overwritten: disk has (%q, %q)", c.AccessToken, c.RefreshToken)
	}
	if got != "jwt-other-org" {
		t.Fatalf("refreshBearer = %q, want the newer credential that is on disk", got)
	}
}

// Edge discovery and the mesh can both want a fresh token at the same moment. A
// refresh token is good for one exchange, so unserialised they spend the same one
// and the second is refused.
func TestRefreshBearerSerialisesConcurrentCallers(t *testing.T) {
	srv := refreshServer(t, "usr_r0", func() { time.Sleep(50 * time.Millisecond) })
	useRefreshCreds(t, srv, &creds.Config{AccessToken: "jwt-0", RefreshToken: "usr_r0"})

	var wg sync.WaitGroup
	got := make([]string, 2)
	for i := range got {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i] = refreshBearer(context.Background())
		}()
	}
	wg.Wait()
	for i, g := range got {
		if g == "" {
			t.Fatalf("caller %d came back empty-handed (%q): it spent a refresh token the other had already rotated", i, got)
		}
	}
}
