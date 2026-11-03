package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBrowserPairSingleUseExpiryAndInstance(t *testing.T) {
	a := newBrowserAuth()
	now := time.Unix(10000, 0)
	a.now = func() time.Time { return now }
	pair, _ := a.issuePair()
	if _, _, ok := newBrowserAuth().exchange(pair, "host", "browser"); ok {
		t.Fatal("cross-instance pairing")
	}
	var success atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, ok := a.exchange(pair, "host", "browser"); ok {
				success.Add(1)
			}
		}()
	}
	wg.Wait()
	if success.Load() != 1 {
		t.Fatalf("concurrent redemption succeeded %d times", success.Load())
	}
	pair, _ = a.issuePair()
	now = now.Add(browserPairTTL)
	if _, _, ok := a.exchange(pair, "host", "browser"); ok {
		t.Fatal("expired pairing accepted")
	}
	for _, bad := range []string{"", strings.Repeat("z", 64), strings.Repeat("a", 64), pair} {
		if _, _, ok := a.exchange(bad, "host", "browser"); ok {
			t.Fatal("invalid/legacy pairing accepted")
		}
	}
}

func TestBrowserSessionIdleAbsoluteAndRevocation(t *testing.T) {
	a := newBrowserAuth()
	now := time.Unix(10000, 0)
	a.now = func() time.Time { return now }
	login := func() (string, browserSession) {
		t.Helper()
		pair, _ := a.issuePair()
		token, s, ok := a.exchange(pair, "host", "browser")
		if !ok {
			t.Fatal("pair failed")
		}
		return token, s
	}
	token, _ := login()
	if _, ok := a.authorize(token, "other-host", true); ok {
		t.Fatal("session crossed host")
	}
	if _, ok := newBrowserAuth().authorize(token, "host", false); ok {
		t.Fatal("session survived restart")
	}
	now = now.Add(29 * time.Minute)
	if _, ok := a.authorize(token, "host", false); !ok {
		t.Fatal("premature expiry")
	}
	now = now.Add(time.Minute)
	if _, ok := a.authorize(token, "host", false); ok {
		t.Fatal("background poll renewed idle deadline")
	}
	token, _ = login()
	for range 23 {
		now = now.Add(20 * time.Minute)
		if _, ok := a.authorize(token, "host", true); !ok {
			t.Fatal("active session expired early")
		}
	}
	now = now.Add(20 * time.Minute)
	if _, ok := a.authorize(token, "host", true); ok {
		t.Fatal("absolute deadline renewed")
	}
	first, s1 := login()
	second, s2 := login()
	if !a.revoke(first, "host", s2.ID, false) {
		t.Fatal("targeted revoke failed")
	}
	if _, ok := a.authorize(second, "host", false); ok {
		t.Fatal("revoked session accepted")
	}
	if _, ok := a.authorize(first, "host", false); !ok {
		t.Fatal("unrelated session revoked")
	}
	if !a.revoke(first, "host", s1.ID, false) {
		t.Fatal("logout failed")
	}
	if _, ok := a.authorize(first, "host", false); ok {
		t.Fatal("copied logout cookie accepted")
	}
	first, _ = login()
	pair, _ := a.issuePair()
	if !a.revoke(first, "host", "", true) {
		t.Fatal("revoke all failed")
	}
	if _, _, ok := a.exchange(pair, "host", "browser"); ok {
		t.Fatal("pending pairing survived revoke all")
	}
	if _, ok := a.authorize(first, "host", false); ok {
		t.Fatal("session survived revoke all")
	}
}

func TestBrowserAuthBoundsAndPruning(t *testing.T) {
	a := newBrowserAuth()
	now := time.Unix(10000, 0)
	a.now = func() time.Time { return now }
	for range browserAuthLimit {
		if _, err := a.issuePair(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.issuePair(); err == nil {
		t.Fatal("pairing bound missing")
	}
	now = now.Add(browserPairTTL)
	for range browserAuthLimit {
		pair, err := a.issuePair()
		if err != nil {
			t.Fatal(err)
		}
		if _, _, ok := a.exchange(pair, "host", "browser"); !ok {
			t.Fatal("session failed")
		}
	}
	pair, _ := a.issuePair()
	if _, _, ok := a.exchange(pair, "host", "browser"); ok {
		t.Fatal("session bound missing")
	}
	now = now.Add(browserIdleTTL)
	pair, _ = a.issuePair()
	if _, _, ok := a.exchange(pair, "host", "browser"); !ok {
		t.Fatal("expired sessions not reclaimed")
	}
}

func TestBrowserHTTPIndependentSessions(t *testing.T) {
	a := newBrowserAuth()
	b := &fileBrowser{authority: "files.example:7500", auth: a, managed: true, action: func(fileAction) (any, error) { return true, nil }}
	request := func(path, body, token, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://"+b.authority+path, strings.NewReader(body))
		r.Header.Set("Origin", origin)
		if token != "" {
			r.AddCookie(&http.Cookie{Name: "calabi_file_browser", Value: token})
		}
		w := httptest.NewRecorder()
		b.ServeHTTP(w, r)
		return w
	}
	pair, _ := a.issuePair()
	if w := request("/file-web/session", `{"pair":"`+pair+`"}`, "", "https://evil.example"); w.Code != 403 {
		t.Fatal("cross-site pairing accepted")
	}
	w := request("/file-web/session", `{"pair":"`+pair+`"}`, "", "https://"+b.authority)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	if cookie.Value == pair || !cookie.HttpOnly || !cookie.Secure || cookie.Path != "/file-service/file-web/" || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe session cookie", cookie)
	}
	if strings.Contains(w.Body.String(), cookie.Value) || strings.Contains(w.Body.String(), pair) {
		t.Fatal("secret disclosed")
	}
	if got := request("/file-web/session", `{"pair":"`+pair+`"}`, "", "https://"+b.authority); got.Code != 401 {
		t.Fatal("pair replay accepted")
	}
	if got := request("/file-web/action", `{"action":"snapshot"}`, pair, "https://"+b.authority); got.Code != 401 {
		t.Fatal("pairing used as session")
	}
	if got := request("/file-web/action", `{"action":"snapshot"}`, strings.Repeat("a", 64), "https://"+b.authority); got.Code != 401 {
		t.Fatal("legacy/console credential accepted")
	}
	var session browserSession
	if err := json.Unmarshal(w.Body.Bytes(), &session); err != nil || session.ID == "" {
		t.Fatal("missing public session ID")
	}
	if got := request("/file-web/logout", `{}`, cookie.Value, "https://"+b.authority); got.Code != 200 {
		t.Fatal("logout failed")
	}
	if got := request("/file-web/action", `{"action":"snapshot"}`, cookie.Value, "https://"+b.authority); got.Code != 401 {
		t.Fatal("copied cookie survived logout")
	}
}
