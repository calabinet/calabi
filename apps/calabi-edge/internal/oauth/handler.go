package oauth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/calabi/calabi/apps/calabi-edge/internal/visitorerr"
)

// Result tells the listener what to do after Handle.
type Result int

const (
	// Allow: the visitor has a valid session; forward the request upstream.
	Allow Result = iota
	// Handled: the edge wrote a response (IdP redirect / callback / error);
	// the listener must NOT forward — close after the response.
	Handled
)

// RequestInfo is the slice of the visitor's request the OAuth flow needs.
type RequestInfo struct {
	Path   string // request target incl. query (e.g. /__calabi/oauth/callback?code=…)
	Host   string // Host header (no scheme)
	HTTPS  bool   // visitor reached us over the TLS-terminating listener
	Cookie string // raw Cookie header value
}

// sharedClient reaches the IdP. Bounded timeout so a slow IdP can't pin a
// visitor connection (or an edge goroutine) indefinitely.
var sharedClient = &http.Client{Timeout: 10 * time.Second}

// Handle runs the OAuth flow for one visitor request, writing any redirect /
// callback / error response directly to w. Returns Allow when the visitor
// already has a valid session and the request should be proxied upstream.
func (c *Config) Handle(w io.Writer, ri RequestInfo, now time.Time) Result {
	path, query := splitPathQuery(ri.Path)
	scheme := "http"
	if ri.HTTPS {
		scheme = "https"
	}
	redirectURI := scheme + "://" + ri.Host + CallbackPath

	switch {
	case path == CallbackPath:
		c.handleCallback(w, query, redirectURI, now)
		return Handled
	case c.validSession(ri.Cookie, now):
		return Allow
	default:
		// Unauthenticated → bounce to the IdP, remembering where to return.
		writeRedirect(w, c.authRedirectURL(redirectURI, c.issueState(ri.Path, now)), "")
		return Handled
	}
}

func (c *Config) handleCallback(w io.Writer, query, redirectURI string, now time.Time) {
	q, _ := url.ParseQuery(query)
	code := q.Get("code")
	state := q.Get("state")
	if code == "" || state == "" {
		writeError(w, http.StatusBadRequest, visitorerr.ErrSignInFailed)
		return
	}
	origPath, ok := c.verifyState(state, now)
	if !ok {
		writeError(w, http.StatusBadRequest, visitorerr.ErrSignInFailed)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	token, err := c.exchangeCode(ctx, sharedClient, code, redirectURI)
	if err != nil {
		writeError(w, http.StatusBadGateway, visitorerr.ErrSignInFailed)
		return
	}
	email, err := providers[c.provider].fetchEmail(ctx, sharedClient, token)
	if err != nil {
		writeError(w, http.StatusBadGateway, visitorerr.ErrSignInFailed)
		return
	}
	if !c.emailAllowed(email) {
		writeError(w, http.StatusForbidden, visitorerr.ErrSignInDenied)
		return
	}
	cookie := cookieName + "=" + c.issueSessionCookie(email, now) +
		"; Path=/; HttpOnly; SameSite=Lax; Max-Age=" + fmt.Sprint(int(sessionTTL.Seconds()))
	writeRedirect(w, origPath, cookie)
}

// splitPathQuery splits a request target into path and raw query.
func splitPathQuery(target string) (path, query string) {
	if i := strings.IndexByte(target, '?'); i >= 0 {
		return target[:i], target[i+1:]
	}
	return target, ""
}

// sanitizeHeader strips CR/LF so a redirect/cookie value can't split the
// response. Our locations come from signed state or url.Values, but this is
// cheap defense in depth.
func sanitizeHeader(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

func writeRedirect(w io.Writer, location, setCookie string) {
	var b strings.Builder
	b.WriteString("HTTP/1.1 302 Found\r\n")
	b.WriteString("Location: " + sanitizeHeader(location) + "\r\n")
	if setCookie != "" {
		b.WriteString("Set-Cookie: " + sanitizeHeader(setCookie) + "\r\n")
	}
	b.WriteString("Cache-Control: no-store\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	_, _ = io.WriteString(w, b.String())
}

// writeError renders the same branded page every other refusal in the edge
// uses. It used to write a bare line of text naming the internal failure
// ("oauth: sign-in failed (token exchange)") — no code to quote at support, no
// page, and a phrase that means nothing to whoever is reading it. That it was
// different was structural, not deliberate: listener -> policy -> oauth, so
// this package could not reach the page until the page moved to visitorerr.
//
// HTML unconditionally: every one of these is reached by a BROWSER following
// the identity provider's redirect. There is no curl in this flow to spare.
func writeError(w io.Writer, code int, errCode string) {
	visitorerr.Write(w, visitorerr.Options{
		HTML:       true,
		Status:     code,
		StatusText: httpReason(code),
		Code:       errCode,
	})
}

func httpReason(code int) string {
	switch code {
	case http.StatusBadRequest:
		return "Bad Request"
	case http.StatusForbidden:
		return "Forbidden"
	case http.StatusBadGateway:
		return "Bad Gateway"
	default:
		return "Error"
	}
}
