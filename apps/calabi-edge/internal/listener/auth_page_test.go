// auth_page_test.go — the Basic-auth 401 is the one refusal that has to be two
// things at once, and it used to be only one.
//
// It was a bare line of text:
//
//	HTTP/1.1 401 Unauthorized
//	WWW-Authenticate: Basic realm="Restricted"
//	Content-Type: text/plain
//
//	401 Unauthorized
//
// The header is load-bearing — without it the browser never prompts — but the
// BODY is what the visitor sees the instant they press Cancel, and it was the
// only refusal in the edge with no branding and no code to quote at support.
//
// The obvious fix (route it through writeVisitorError like everything else)
// drops the header and silently breaks password-protected tunnels: no prompt
// ever appears again. So this file pins BOTH halves against each other.
//
// RUN: go test./apps/calabi-edge/internal/listener/ -run TestAuthPage -v
package listener

import (
	"bytes"
	"strings"
	"testing"

	"github.com/calabinet/calabi/apps/calabi-edge/internal/visitorerr"
)

func TestAuthPageKeepsTheChallengeHeader(t *testing.T) {
	for _, tc := range []struct {
		name string
		head []byte
	}{
		{"browser", browserHead()},
		{"curl", curlHead()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			write401(&buf, tc.head, basicAuthRealm)
			resp, body := parseResponse(t, buf.Bytes())

			if resp.StatusCode != 401 {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
			got := resp.Header.Get("WWW-Authenticate")
			if !strings.HasPrefix(got, "Basic realm=") {
				t.Fatalf("WWW-Authenticate = %q — without it the browser never "+
					"prompts, and a password-protected tunnel becomes unreachable "+
					"rather than protected", got)
			}
			if !strings.Contains(got, basicAuthRealm) {
				t.Fatalf("realm missing from %q; browsers key cached credentials on it", got)
			}
			// …and it is no longer a bare line: the visitor gets something to read
			// and something to quote.
			if !strings.Contains(body, visitorerr.ErrAuthRequired) {
				t.Fatalf("body carries no error code:\n%s", body)
			}
			if strings.TrimSpace(body) == "401 Unauthorized" {
				t.Fatal("still the bare pre-fix body")
			}
		})
	}
}

// A browser gets the page; curl gets one line. Same split as every other
// refusal — a terminal full of markup is worse than a sentence.
func TestAuthPageShapeFollowsAccept(t *testing.T) {
	var html, text bytes.Buffer
	write401(&html, browserHead(), basicAuthRealm)
	write401(&text, curlHead(), basicAuthRealm)

	hResp, hBody := parseResponse(t, html.Bytes())
	tResp, tBody := parseResponse(t, text.Bytes())

	if ct := hResp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("browser Content-Type = %q, want text/html", ct)
	}
	if !strings.Contains(hBody, "<svg") {
		t.Fatal("the page has no warning mark")
	}
	if ct := tResp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("curl Content-Type = %q, want text/plain", ct)
	}
	if strings.Contains(tBody, "<") {
		t.Fatalf("markup reached a non-browser:\n%s", tBody)
	}
}
