package statusapi

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/calabi/calabi/apps/client/internal/creds"
)

// Nobody signed in is known without asking bff-console: /v1/me answers 401 on
// its own, so a machine that cannot reach calabi.net still gets the sign-in
// page — and on it the way to a self-hosted server. With something to sign in
// with (even only a refresh token), bff-console is asked as before.
func TestMeWithoutAnyCredentialIsAnsweredLocally(t *testing.T) {
	isolateCreds(t)
	t.Setenv("CALABI_API_KEY", "")
	t.Setenv("CALABI_TOKEN", "")
	var calls atomic.Int32
	bff := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"user":{"id":7,"email":"kenji@example.com"}}`))
	}))
	defer bff.Close()
	s := New(nil, Config{BFFConsoleURL: bff.URL})
	mux := http.NewServeMux()
	s.Register(mux)

	get := func() int {
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest("GET", "/v1/me", nil))
		return rr.Code
	}
	if code := get(); code != http.StatusUnauthorized || calls.Load() != 0 {
		t.Fatalf("no credential: %d after %d calls to bff-console; want 401 and none", code, calls.Load())
	}
	if err := creds.Save(&creds.Config{RefreshToken: "rt"}); err != nil {
		t.Fatal(err)
	}
	get()
	if calls.Load() == 0 {
		t.Fatal("with a refresh token stored, bff-console was not asked")
	}
	if err := creds.Save(&creds.Config{AccessToken: "jwt"}); err != nil {
		t.Fatal(err)
	}
	if code := get(); code != http.StatusOK {
		t.Fatalf("signed in: %d", code)
	}
}
