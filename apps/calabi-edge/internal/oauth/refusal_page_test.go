// refusal_page_test.go — a refused sign-in looks like every other refusal.
//
// It did not. This package wrote a bare line naming its own internals:
//
//	oauth: sign-in failed (token exchange)
//
// No page, no code to quote at support, and a phrase that means nothing to the
// person reading it. Every other way the edge says no had a branded page with a
// CAL-XXXX code on it.
//
// The reason was structural rather than deliberate — `listener -> policy ->
// oauth`, so this package could not import the page. Moving the page to
// internal/visitorerr (which imports nothing of ours) is what let this file
// exist, and this file is what stops it drifting back: it asserts through
// handleCallback, not through writeError, so removing the call site fails it.
//
// RUN: go test./apps/calabi-edge/internal/oauth/ -run TestRefusalPage -v
package oauth

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/calabi-edge/internal/visitorerr"
)

// A callback with nothing in it is the one refusal reachable with no identity
// provider on the other end, so it is what the wiring can be tested through.
func TestRefusalPageCallbackWithoutCodeRendersThePage(t *testing.T) {
	c, err := New("google", "cid", "sec", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	c.handleCallback(&buf, "", "https://t.example/__calabi/oauth/callback", time.Unix(1_700_000_000, 0))
	out := buf.String()

	if !strings.Contains(out, visitorerr.ErrSignInFailed) {
		t.Fatalf("no error code in the response — nothing for the visitor to quote:\n%s", out)
	}
	if !strings.Contains(out, "<svg") || !strings.Contains(out, "<h1>") {
		t.Fatalf("not the branded page:\n%s", out)
	}
	if strings.Contains(out, "missing code or state") || strings.Contains(out, "oauth:") {
		t.Fatalf("internal phrasing reached the visitor:\n%s", out)
	}
	if !strings.Contains(out, "Cache-Control: no-store") {
		t.Fatal("a refusal must not be cacheable")
	}
}

// The two sign-in outcomes are deliberately different codes: "we could not
// finish signing you in" is fixed by trying again, "your account is not on the
// list" is fixed by asking the owner. One code for both would send every
// visitor down the wrong path half the time.
func TestRefusalPageSeparatesFailedFromDenied(t *testing.T) {
	if visitorerr.ErrSignInFailed == visitorerr.ErrSignInDenied {
		t.Fatal("the two sign-in outcomes share a code")
	}
	failed, denied := visitorerr.Bodies[visitorerr.ErrSignInFailed], visitorerr.Bodies[visitorerr.ErrSignInDenied]
	if failed.Headline == "" || denied.Headline == "" {
		t.Fatal("a code with no page renders the internal fallback")
	}
	if failed.Headline == denied.Headline {
		t.Fatalf("both outcomes say %q, so the code is the only thing telling them apart",
			failed.Headline)
	}
}
