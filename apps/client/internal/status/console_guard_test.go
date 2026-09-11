package status

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	thisMachine = "127.0.0.1:52001"
	otherPeer   = "192.0.2.5:52002"
	consoleHost = "192.0.2.1:7400" // how a visitor from another machine addresses the console
	testSecret  = "abcdef-ghijkl-mnopqr-stuvwx"
)

// guardUnderTest wires the real guard in front of a handler that records whether
// the request got through. secret "" = no secret configured.
func guardUnderTest(t *testing.T, secret string) (http.Handler, *Server, *bool) {
	t.Helper()
	s := NewServer(slog.New(slog.NewTextHandler(io.Discard, nil)), New("test", ""), "127.0.0.1:0")
	s.SetConsoleSecret(secret)
	reached := new(bool)
	h := s.consoleGuard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*reached = true
		w.WriteHeader(http.StatusOK)
	}))
	return h, s, reached
}

type consoleReq struct {
	method, path, peer, host, origin, body string
	cookie                                 *http.Cookie
	fetchSite                              string
}

func (c consoleReq) do(h http.Handler) *httptest.ResponseRecorder {
	method := c.method
	if method == "" {
		method = "GET"
	}
	req := httptest.NewRequest(method, c.path, strings.NewReader(c.body))
	req.RemoteAddr = c.peer
	req.Host = c.host
	if c.origin != "" {
		req.Header.Set("Origin", c.origin)
	}
	if c.fetchSite != "" {
		req.Header.Set("Sec-Fetch-Site", c.fetchSite)
	}
	if c.cookie != nil {
		req.AddCookie(c.cookie)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func jsonField(t *testing.T, rr *httptest.ResponseRecorder, key string) any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("response is not JSON (%d): %q", rr.Code, rr.Body.String())
	}
	return m[key]
}

func sessionCookie(t *testing.T, rr *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rr.Result().Cookies() {
		if strings.HasPrefix(c.Name, "calabi_console") {
			return c
		}
	}
	return nil
}

func unlock(h http.Handler, peer, host, secret string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(map[string]string{"secret": secret})
	return consoleReq{method: "POST", path: consoleUnlockPath, peer: peer, host: host,
		origin: "http://" + host, body: string(b)}.do(h)
}

// A request that did not come from this machine must not be treated as local
// just because it SAYS it is addressed to localhost.
//
// consoleGuard (MESH-9) decided "local" from the Host header alone. That stops a
// browser — a page cannot forge Host — but the header is the client's to write,
// so on a console bound beyond loopback (the documented Docker set-up) anyone on
// the network got the whole /v1 surface, write token included, by sending
// `Host: localhost`. Began as the repro (it failed against the Host-only guard).
func TestConsoleGuard_ForgedLoopbackHostFromTheNetworkIsNotLocal(t *testing.T) {
	for _, secret := range []string{"", testSecret} {
		h, _, reached := guardUnderTest(t, secret)
		rr := consoleReq{path: "/v1/local-token", peer: "192.0.2.10:52814", host: "localhost:7400"}.do(h)
		if *reached {
			t.Fatalf("secret=%q: a network peer claiming Host: localhost reached the API (status %d)", secret, rr.Code)
		}
	}
}

// The console's owner — a caller on this machine, by a local name — needs no
// secret, however it spells the name.
func TestConsoleGuard_ThisMachineNeedsNoSecret(t *testing.T) {
	h, _, reached := guardUnderTest(t, testSecret)
	for _, host := range []string{"127.0.0.1:7400", "localhost:7400", "[::1]:7400", "app.localhost:7400",
		"0.0.0.0:7400" /* the CLI dialling a console bound to 0.0.0.0 */} {
		*reached = false
		if rr := (consoleReq{path: "/v1/me", peer: thisMachine, host: host}).do(h); !*reached {
			t.Errorf("Host %s from this machine: status %d, want it served", host, rr.Code)
		}
	}
	*reached = false
	if rr := (consoleReq{path: "/v1/me", peer: "[::1]:52003", host: "localhost:7400"}).do(h); !*reached {
		t.Errorf("IPv6 loopback peer: status %d, want it served", rr.Code)
	}
}

// A DNS-rebinding page connects from this very machine, but under its own name:
// it gets the lock, and without a secret configured, the old refusal.
func TestConsoleGuard_RebindingPageIsLocked(t *testing.T) {
	rebound := consoleReq{path: "/v1/local-token", peer: thisMachine, host: "rebind.evil.example:7400",
		origin: "http://rebind.evil.example:7400"}

	h, _, reached := guardUnderTest(t, testSecret)
	rr := rebound.do(h)
	if *reached || rr.Code != http.StatusUnauthorized || jsonField(t, rr, "error") != "console_locked" {
		t.Fatalf("rebound with a secret: reached=%v status=%d body=%s, want 401 console_locked", *reached, rr.Code, rr.Body)
	}

	h, _, reached = guardUnderTest(t, "")
	if rr := rebound.do(h); *reached || rr.Code != http.StatusMisdirectedRequest {
		t.Fatalf("rebound without a secret: reached=%v status=%d, want 421", *reached, rr.Code)
	}
}

// The feature, end to end: locked until the right secret, then served on the
// session cookie.
func TestConsoleGuard_VisitorUnlocksWithTheSecret(t *testing.T) {
	h, _, reached := guardUnderTest(t, testSecret)
	origin := "http://" + consoleHost

	rr := consoleReq{path: "/v1/me", peer: otherPeer, host: consoleHost, origin: origin}.do(h)
	if *reached || rr.Code != http.StatusUnauthorized || jsonField(t, rr, "error") != "console_locked" {
		t.Fatalf("before unlocking: reached=%v status=%d, want 401 console_locked", *reached, rr.Code)
	}
	rr = consoleReq{path: consoleStatePath, peer: otherPeer, host: consoleHost, origin: origin}.do(h)
	if jsonField(t, rr, "locked") != true || jsonField(t, rr, "remote") != true || jsonField(t, rr, "unlock_available") != true {
		t.Fatalf("state before unlocking = %s", rr.Body)
	}

	rr = unlock(h, otherPeer, consoleHost, "not-the-secret")
	if rr.Code != http.StatusUnauthorized || jsonField(t, rr, "error") != "console_unlock_failed" || sessionCookie(t, rr) != nil {
		t.Fatalf("wrong secret: status=%d cookie=%v, want 401 and no session", rr.Code, sessionCookie(t, rr))
	}

	rr = unlock(h, otherPeer, consoleHost, "  "+testSecret+"\n") // pasted with whitespace
	c := sessionCookie(t, rr)
	if rr.Code != http.StatusOK || c == nil {
		t.Fatalf("right secret: status=%d cookie=%v, want 200 and a session", rr.Code, c)
	}
	if c.Name != "calabi_console_7400" || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie = %+v, want calabi_console_7400, HttpOnly, SameSite=Strict", c)
	}

	*reached = false
	if rr := (consoleReq{path: "/v1/me", peer: otherPeer, host: consoleHost, origin: origin, cookie: c}).do(h); !*reached {
		t.Fatalf("with the session: status %d, want it served", rr.Code)
	}
	rr = consoleReq{path: consoleStatePath, peer: otherPeer, host: consoleHost, cookie: c}.do(h)
	if jsonField(t, rr, "locked") != false {
		t.Fatalf("state with the session = %s", rr.Body)
	}
}

// Another site cannot drive the unlock (or anything else), right secret or not.
func TestConsoleGuard_CrossSiteRefusedEvenWithTheSecret(t *testing.T) {
	h, _, _ := guardUnderTest(t, testSecret)
	body, _ := json.Marshal(map[string]string{"secret": testSecret})
	for _, r := range []consoleReq{
		{method: "POST", path: consoleUnlockPath, peer: otherPeer, host: consoleHost, origin: "https://evil.example", body: string(body)},
		{method: "POST", path: consoleUnlockPath, peer: otherPeer, host: consoleHost, fetchSite: "cross-site", body: string(body)},
	} {
		if rr := r.do(h); rr.Code != http.StatusForbidden || sessionCookie(t, rr) != nil {
			t.Fatalf("cross-site unlock: status=%d, want 403 and no session", rr.Code)
		}
	}
}

// Five wrong guesses from one peer pause that peer — not everyone — and the
// pause ends on its own.
func TestConsoleGuard_UnlockGuessesAreRateLimited(t *testing.T) {
	h, s, _ := guardUnderTest(t, testSecret)
	clock := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	s.lock.now = func() time.Time { return clock }

	for i := 0; i < unlockFailsPerPeer; i++ {
		if rr := unlock(h, otherPeer, consoleHost, "guess"); rr.Code != http.StatusUnauthorized {
			t.Fatalf("guess %d: status %d, want 401", i+1, rr.Code)
		}
	}
	rr := unlock(h, otherPeer, consoleHost, testSecret)
	if rr.Code != http.StatusTooManyRequests || rr.Header().Get("Retry-After") == "" || sessionCookie(t, rr) != nil {
		t.Fatalf("after %d misses even the right secret must wait: status=%d retry-after=%q",
			unlockFailsPerPeer, rr.Code, rr.Header().Get("Retry-After"))
	}
	if rr := unlock(h, "192.0.2.6:1", consoleHost, testSecret); rr.Code != http.StatusOK {
		t.Fatalf("another peer was paused too: status %d", rr.Code)
	}
	clock = clock.Add(unlockFailWindow + time.Second)
	if rr := unlock(h, otherPeer, consoleHost, testSecret); rr.Code != http.StatusOK {
		t.Fatalf("the pause did not lift: status %d", rr.Code)
	}
}

// Spreading guesses across addresses does not multiply the budget.
func TestConsoleGuard_GlobalGuessBudget(t *testing.T) {
	h, s, _ := guardUnderTest(t, testSecret)
	clock := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	s.lock.now = func() time.Time { return clock }
	for i := 0; i < unlockGlobalFails; i++ {
		unlock(h, "198.51.100."+strconv.Itoa(i)+":1", consoleHost, "guess")
	}
	if rr := unlock(h, "203.0.113.9:1", consoleHost, testSecret); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("a fresh peer after %d misses platform-wide: status %d, want 429", unlockGlobalFails, rr.Code)
	}
}

// An unlock lasts consoleSessionTTL and no longer.
func TestConsoleGuard_SessionExpires(t *testing.T) {
	h, s, reached := guardUnderTest(t, testSecret)
	clock := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	s.lock.now = func() time.Time { return clock }
	c := sessionCookie(t, unlock(h, otherPeer, consoleHost, testSecret))
	clock = clock.Add(consoleSessionTTL)
	if rr := (consoleReq{path: "/v1/me", peer: otherPeer, host: consoleHost, cookie: c}).do(h); *reached || rr.Code != http.StatusUnauthorized {
		t.Fatalf("an expired session was honoured: status %d", rr.Code)
	}
}

// Two consoles on one machine keep separate sessions.
func TestConsoleGuard_SessionIsPerConsolePort(t *testing.T) {
	h, _, reached := guardUnderTest(t, testSecret)
	c := sessionCookie(t, unlock(h, otherPeer, consoleHost, testSecret))
	if rr := (consoleReq{path: "/v1/me", peer: otherPeer, host: "192.0.2.1:7401", cookie: c}).do(h); *reached || rr.Code != http.StatusUnauthorized {
		t.Fatalf("the :7400 session opened the :7401 console: status %d", rr.Code)
	}
}

// What never carried authority stays reachable from anywhere.
func TestConsoleGuard_NonAPIPathsUntouched(t *testing.T) {
	h, _, reached := guardUnderTest(t, testSecret)
	for _, p := range []string{"/", "/assets/index-abc.js", "/healthz", "/metrics"} {
		*reached = false
		if rr := (consoleReq{path: p, peer: otherPeer, host: consoleHost}).do(h); !*reached {
			t.Errorf("%s from another machine: status %d, want it served", p, rr.Code)
		}
	}
}

// On this machine there is nothing to unlock, and the state says so.
func TestConsoleGuard_LocalStateAndUnlock(t *testing.T) {
	h, _, _ := guardUnderTest(t, "")
	rr := consoleReq{path: consoleStatePath, peer: thisMachine, host: "127.0.0.1:7400"}.do(h)
	if jsonField(t, rr, "locked") != false || jsonField(t, rr, "remote") != false {
		t.Fatalf("local state = %s", rr.Body)
	}
	rr = consoleReq{method: "POST", path: consoleUnlockPath, peer: thisMachine, host: "127.0.0.1:7400", body: `{}`}.do(h)
	if rr.Code != http.StatusOK || sessionCookie(t, rr) != nil {
		t.Fatalf("local unlock: status %d, want 200 and no cookie", rr.Code)
	}
	// Without a secret, a remote visitor learns the lock cannot be opened here.
	rr = consoleReq{path: consoleStatePath, peer: otherPeer, host: consoleHost}.do(h)
	if jsonField(t, rr, "locked") != true || jsonField(t, rr, "unlock_available") != false {
		t.Fatalf("remote state without a secret = %s", rr.Body)
	}
}
