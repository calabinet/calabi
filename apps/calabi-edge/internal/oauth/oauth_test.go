package oauth

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestNew_Validation(t *testing.T) {
	if _, err := New("nope", "a", "b", nil, nil); err == nil {
		t.Fatal("unsupported provider must error")
	}
	if _, err := New("google", "", "b", nil, nil); err == nil {
		t.Fatal("missing client_id must error")
	}
	if _, err := New("github", "a", "", nil, nil); err == nil {
		t.Fatal("missing client_secret must error")
	}
	if _, err := New("GitHub", "a", "b", nil, nil); err != nil {
		t.Fatalf("provider name should be case-insensitive: %v", err)
	}
}

func TestSessionCookieRoundtrip(t *testing.T) {
	c, _ := New("google", "cid", "sec", []string{"a@x.com"}, nil)
	now := time.Unix(1_700_000_000, 0)
	header := cookieName + "=" + c.issueSessionCookie("a@x.com", now)

	if !c.validSession(header, now) {
		t.Fatal("a fresh, allow-listed cookie must validate")
	}
	if c.validSession(header, now.Add(sessionTTL+time.Second)) {
		t.Fatal("an expired cookie must fail")
	}
	if c.validSession(cookieName+"="+"tampered.sig", now) {
		t.Fatal("a tampered cookie must fail")
	}
	if other, _ := New("google", "cid", "OTHER", []string{"a@x.com"}, nil); other.validSession(header, now) {
		t.Fatal("a cookie signed with a different secret must fail")
	}
	// Policy revoked the email → re-check on every request must reject it even
	// though the signature is still valid.
	if revoked, _ := New("google", "cid", "sec", []string{"b@x.com"}, nil); revoked.validSession(header, now) {
		t.Fatal("a now-unlisted email must fail the per-request allow re-check")
	}
}

func TestStateRoundtrip(t *testing.T) {
	c, _ := New("github", "cid", "sec", nil, nil)
	now := time.Unix(1_700_000_000, 0)
	st := c.issueState("/dashboard?x=1", now)
	if p, ok := c.verifyState(st, now); !ok || p != "/dashboard?x=1" {
		t.Fatalf("state roundtrip: ok=%v path=%q", ok, p)
	}
	if _, ok := c.verifyState(st, now.Add(stateTTL+time.Second)); ok {
		t.Fatal("expired state must fail")
	}
	if _, ok := c.verifyState(st+"x", now); ok {
		t.Fatal("tampered state must fail")
	}
	// The callback path can't be the post-login redirect target (loop guard).
	if p, _ := c.verifyState(c.issueState(CallbackPath, now), now); p != "/" {
		t.Fatalf("callback origin should collapse to /, got %q", p)
	}
}

func TestEmailAllowed(t *testing.T) {
	anyUser, _ := New("google", "c", "s", nil, nil)
	if !anyUser.emailAllowed("anyone@whatever.com") {
		t.Fatal("empty allow-lists mean any verified email is allowed")
	}
	if anyUser.emailAllowed("") {
		t.Fatal("an empty email is never allowed")
	}
	byEmail, _ := New("google", "c", "s", []string{"Alice@ACME.com"}, nil)
	if !byEmail.emailAllowed("alice@acme.com") {
		t.Fatal("email match must be case-insensitive")
	}
	if byEmail.emailAllowed("bob@acme.com") {
		t.Fatal("a non-listed email must be denied")
	}
	byDomain, _ := New("google", "c", "s", nil, []string{"acme.com"})
	if !byDomain.emailAllowed("bob@ACME.com") {
		t.Fatal("domain match must be case-insensitive")
	}
	if byDomain.emailAllowed("bob@evil.com") {
		t.Fatal("another domain must be denied")
	}
}

func TestHandle_RedirectThenAllow(t *testing.T) {
	c, _ := New("google", "cid", "sec", nil, nil)
	now := time.Unix(1_700_000_000, 0)

	var buf bytes.Buffer
	if r := c.Handle(&buf, RequestInfo{Path: "/app", Host: "t.example", HTTPS: true}, now); r != Handled {
		t.Fatal("an unauthenticated request must be Handled (redirected)")
	}
	out := buf.String()
	if !strings.Contains(out, "302 Found") || !strings.Contains(out, "accounts.google.com") {
		t.Fatalf("expected a 302 to Google; got %q", out)
	}
	if !strings.Contains(out, "redirect_uri=https%3A%2F%2Ft.example%2F__calabi%2Foauth%2Fcallback") {
		t.Fatalf("redirect_uri not built from host + callback path: %q", out)
	}

	header := cookieName + "=" + c.issueSessionCookie("u@x.com", now)
	if r := c.Handle(&buf, RequestInfo{Path: "/app", Host: "t.example", HTTPS: true, Cookie: header}, now); r != Allow {
		t.Fatal("a request with a valid session cookie must be Allowed")
	}
}
