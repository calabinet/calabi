// errorpage_test.go — what a stranger is allowed to learn from a refusal, and
// what shape it arrives in.
//
// RUN: go test./apps/calabi-edge/internal/listener/ -run TestErrorPage -v
package listener

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/calabinet/calabi/apps/calabi-edge/internal/visitorerr"
)

// parseResponse reads what a listener wrote onto the visitor conn back into an
// http.Response, so the assertions are about the real thing rather than about
// substrings of a hand-built string.
func parseResponse(t *testing.T, raw []byte) (*http.Response, string) {
	t.Helper()
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), nil)
	if err != nil {
		t.Fatalf("the bytes written are not a valid HTTP response: %v\n%s", err, raw)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, string(body)
}

func browserHead() []byte {
	return []byte("GET / HTTP/1.1\r\nHost: x.example\r\nAccept: text/html,application/xhtml+xml\r\n\r\n")
}

func curlHead() []byte {
	return []byte("GET / HTTP/1.1\r\nHost: x.example\r\nAccept: */*\r\n\r\n")
}

func TestErrorPageBrowserGetsHTML(t *testing.T) {
	var buf bytes.Buffer
	writeVisitorError(&buf, browserHead(), 502, visitorerr.ErrNoTunnel)

	resp, body := parseResponse(t, buf.Bytes())
	if resp.StatusCode != 502 {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", ct)
	}
	if !strings.Contains(body, visitorerr.ErrNoTunnel) {
		t.Fatalf("the page does not carry its code:\n%s", body)
	}
	if !strings.Contains(body, "<!doctype html>") {
		t.Fatalf("not an HTML document:\n%s", body)
	}
}

// curl sends Accept: */*. Filling a terminal with markup is worse than showing
// one line, so */* is deliberately NOT treated as a browser.
func TestErrorPageNonBrowserGetsText(t *testing.T) {
	for _, head := range [][]byte{curlHead(), []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")} {
		var buf bytes.Buffer
		writeVisitorError(&buf, head, 502, visitorerr.ErrNoTunnel)
		resp, body := parseResponse(t, buf.Bytes())
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
			t.Fatalf("Content-Type = %q, want text/plain", ct)
		}
		if strings.Contains(body, "<html") {
			t.Fatalf("markup went to a non-browser client:\n%s", body)
		}
		// The code has to survive into the text form too — it is the part that
		// makes a support conversation possible.
		if !strings.Contains(body, visitorerr.ErrNoTunnel) {
			t.Fatalf("the text form dropped the code:\n%s", body)
		}
	}
}

// A browser that cached a 502 would keep showing it after the tunnel came back,
// and the user would report a bug that is not one. A search engine that indexed
// one would put "This tunnel is offline" in results for the customer's host.
func TestErrorPageIsNeverCachedOrIndexed(t *testing.T) {
	for _, head := range [][]byte{browserHead(), curlHead()} {
		var buf bytes.Buffer
		writeVisitorError(&buf, head, 502, visitorerr.ErrNoTunnel)
		resp, _ := parseResponse(t, buf.Bytes())
		if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
			t.Fatalf("Cache-Control = %q, want no-store", cc)
		}
		if rt := resp.Header.Get("X-Robots-Tag"); !strings.Contains(rt, "noindex") {
			t.Fatalf("X-Robots-Tag = %q, want noindex", rt)
		}
	}
}

// THE ONE THAT MATTERS. The old body was "upstream unavailable: " + err, and for
// a session blocked over the monthly traffic cap that read
// "session blocked: org over monthly_traffic_mb" — the customer's commercial
// state, served to anyone who typed the hostname.
func TestErrorPageDoesNotLeakWhyASessionIsBlocked(t *testing.T) {
	blocked := errors.New("session blocked: org 42 over monthly_traffic_mb")
	code := upstreamErrCode(blocked)
	if code != visitorerr.ErrUnavailable {
		t.Fatalf("a blocked session maps to %s, want the vague %s", code, visitorerr.ErrUnavailable)
	}

	var buf bytes.Buffer
	writeVisitorError(&buf, browserHead(), 502, code)
	_, body := parseResponse(t, buf.Bytes())
	for _, leak := range []string{"monthly_traffic_mb", "session blocked", "org 42", "42"} {
		if strings.Contains(body, leak) {
			t.Fatalf("the page leaks %q:\n%s", leak, body)
		}
	}
}

// An ordinary upstream failure is NOT vague: the owner is usually the person
// reading it during development, and "check the service is listening" is the
// whole value of the page.
func TestErrorPageIsSpecificWhenItCanBe(t *testing.T) {
	if code := upstreamErrCode(errors.New("dial tcp 127.0.0.1:3000: connection refused")); code != visitorerr.ErrUpstreamDown {
		t.Fatalf("an ordinary upstream failure maps to %s, want %s", code, visitorerr.ErrUpstreamDown)
	}
	var buf bytes.Buffer
	writeVisitorError(&buf, browserHead(), 502, visitorerr.ErrUpstreamDown)
	_, body := parseResponse(t, buf.Bytes())
	if !strings.Contains(body, "listening") {
		t.Fatalf("the page gives the owner nothing to act on:\n%s", body)
	}
	// …but it still must not echo the raw error, which can carry an internal
	// address the visitor has no business seeing.
	if strings.Contains(body, "127.0.0.1:3000") {
		t.Fatalf("the page echoed the upstream address:\n%s", body)
	}
}

// Every code renders, and an unknown one degrades to the internal page instead
// of an empty body.
func TestErrorPageEveryCodeRenders(t *testing.T) {
	// Enumerated from the map, not restated here: a hand-kept list is how a
	// new code ships with no page and nothing goes red. (CAL-1008/1009/1010 —
	// basic auth and the two sign-in outcomes — were added later and were
	// covered by this line the moment they existed.)
	codes := make([]string, 0, len(visitorerr.Bodies))
	for c := range visitorerr.Bodies {
		codes = append(codes, c)
	}
	seen := map[string]bool{}
	for _, c := range codes {
		var buf bytes.Buffer
		writeVisitorError(&buf, browserHead(), 502, c)
		_, body := parseResponse(t, buf.Bytes())
		if !strings.Contains(body, c) {
			t.Fatalf("code %s does not appear in its own page", c)
		}
		headline := visitorerr.Bodies[c].Headline
		if seen[headline] {
			t.Fatalf("code %s reuses another code's headline %q — then the code is the only thing distinguishing them, which defeats having eight", c, headline)
		}
		seen[headline] = true
	}

	var buf bytes.Buffer
	writeVisitorError(&buf, browserHead(), 500, "CAL-9999")
	_, body := parseResponse(t, buf.Bytes())
	if !strings.Contains(body, visitorerr.ErrInternal) {
		t.Fatalf("an unknown code produced %q, want a fallback to %s", body, visitorerr.ErrInternal)
	}
}

// Content-Length has to match the body, or a keep-alive client hangs waiting
// for bytes that never come. http.ReadResponse above already enforces this for
// every case; this pins it for the widest page specifically.
func TestErrorPageContentLengthIsRight(t *testing.T) {
	var buf bytes.Buffer
	writeVisitorError(&buf, browserHead(), 502, visitorerr.ErrUpstreamDown)
	resp, body := parseResponse(t, buf.Bytes())
	if resp.ContentLength != int64(len(body)) {
		t.Fatalf("Content-Length %d != body %d", resp.ContentLength, len(body))
	}
}
