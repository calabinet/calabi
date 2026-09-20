package statusapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/creds"
)

// When the access token expires, every request the local console has in flight
// is refused together. Each of them — /v1/me, the one AuthGate polls, included —
// has to come back with data after ONE refresh. Before, the first request
// refreshed and the rest got "login required" (a 30 s cooldown), so the console
// dropped to its login screen while the session was fine, and a new tab worked.
func TestProxySimultaneous401sAllSucceedAfterOneRefresh(t *testing.T) {
	isolateCreds(t)
	if err := creds.Save(&creds.Config{AccessToken: "jwt-0", RefreshToken: "usr_r0"}); err != nil {
		t.Fatal(err)
	}

	// bff-console with identity-svc's refresh semantics: a refresh token is
	// good for one exchange, rotated on use, a replay refused.
	var (
		mu        sync.Mutex
		current   = "usr_r0"
		n         int
		refreshes atomic.Int32
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/refresh" {
			refreshes.Add(1)
			time.Sleep(30 * time.Millisecond) // the window the other requests queue in
			var in struct {
				RefreshToken string `json:"refresh_token"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			mu.Lock()
			defer mu.Unlock()
			if in.RefreshToken != current {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			n++
			current = fmt.Sprintf("usr_r%d", n)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"access_token":  fmt.Sprintf("jwt-%d", n),
				"refresh_token": current,
			})
			return
		}
		if r.Header.Get("Authorization") != "Bearer jwt-1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"user":{"id":1}}`)
	}))
	defer upstream.Close()

	s := New(nil, Config{BFFConsoleURL: upstream.URL})
	mux := http.NewServeMux()
	s.Register(mux)

	codes := make([]int, 6)
	var wg sync.WaitGroup
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/me", nil))
			codes[i] = rr.Code
		}()
	}
	wg.Wait()

	for i, c := range codes {
		if c != http.StatusOK {
			t.Fatalf("request %d got HTTP %d — the console would show its login screen (all: %v)", i, c, codes)
		}
	}
	if got := refreshes.Load(); got != 1 {
		t.Fatalf("%d refresh exchanges for one expired token, want 1", got)
	}
	if c, _ := creds.Load(); c == nil || c.AccessToken != "jwt-1" || c.RefreshToken != "usr_r1" {
		t.Fatalf("creds after the refresh = %+v, want jwt-1 / usr_r1", c)
	}
}
