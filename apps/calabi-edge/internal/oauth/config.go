// Package oauth implements the edge-side OAuth/OIDC "login wall" (④): the edge
// gates an HTTP/HTTPS tunnel behind an identity provider (Google / GitHub).
// Used to be excluded from the open-source build; since F3 one edge binary
// ships and every edge, self-hosted included, can enforce it.
//
// Model (same request-1 / cookie shape as Basic auth — no per-request byte
// mutation): an unauthenticated visitor is 302-redirected to the IdP; the IdP
// redirects back to the tunnel's callback path; the edge exchanges the code for
// a token, reads the user's email, checks the allow-lists, and sets a SIGNED
// session cookie; subsequent requests carry the cookie and are forwarded.
//
// Stateless + mesh-safe: both the session cookie and the OAuth `state` are
// HMAC-signed with a key DERIVED FROM client_secret, so every edge in a region
// validates them identically without shared server-side state. The config blob
// (incl. client_secret) is server-authoritative — parsed from config_json, the
// edge uses client_secret only to talk to the IdP.
package oauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"
)

// CallbackPath is the fixed path the edge intercepts to complete the OAuth
// handshake (it must be registered as a redirect URI in the IdP app, as
// https://<tunnel-host><CallbackPath>).
const CallbackPath = "/__calabi/oauth/callback"

const (
	cookieName = "__calabi_oauth"
	sessionTTL = 12 * time.Hour
	stateTTL   = 10 * time.Minute
)

// Config is a tunnel's parsed, validated OAuth requirement.
type Config struct {
	provider     string
	clientID     string
	clientSecret string
	allowEmails  map[string]bool // lowercased; empty = any verified email
	allowDomains map[string]bool // lowercased email domains; empty = any
	cookieKey    []byte          // HMAC key for cookie + state, derived from secret
}

// New validates the inputs and derives the signing key. Returns an error for an
// unsupported provider or missing credentials.
func New(provider, clientID, clientSecret string, allowEmails, allowDomains []string) (*Config, error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if _, ok := providers[provider]; !ok {
		return nil, errors.New("oauth: unsupported provider " + provider)
	}
	if strings.TrimSpace(clientID) == "" || strings.TrimSpace(clientSecret) == "" {
		return nil, errors.New("oauth: client_id and client_secret are required")
	}
	sum := sha256.Sum256([]byte(clientSecret + "|calabi-oauth-cookie-v1"))
	return &Config{
		provider:     provider,
		clientID:     strings.TrimSpace(clientID),
		clientSecret: strings.TrimSpace(clientSecret),
		allowEmails:  lowerSet(allowEmails),
		allowDomains: lowerSet(allowDomains),
		cookieKey:    sum[:],
	}, nil
}

func lowerSet(in []string) map[string]bool {
	if len(in) == 0 {
		return nil
	}
	m := make(map[string]bool, len(in))
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" {
			m[s] = true
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

// emailAllowed reports whether an authenticated email passes the allow-lists.
// Empty lists mean "any successfully-authenticated user" (just require login).
func (c *Config) emailAllowed(email string) bool {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return false
	}
	if len(c.allowEmails) == 0 && len(c.allowDomains) == 0 {
		return true
	}
	if c.allowEmails[email] {
		return true
	}
	if at := strings.LastIndexByte(email, '@'); at >= 0 {
		if c.allowDomains[email[at+1:]] {
			return true
		}
	}
	return false
}

// ---- signed tokens (session cookie + OAuth state) ------------------------

// signToken returns "<base64url(payload)>.<base64url(hmac)>".
func signToken(key []byte, payload string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// verifyToken constant-time-checks the signature and returns the payload.
func verifyToken(key []byte, token string) (string, bool) {
	dot := strings.LastIndexByte(token, '.')
	if dot <= 0 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(token[:dot])
	if err != nil {
		return "", false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(token[dot+1:]), []byte(want)) {
		return "", false
	}
	return string(payload), true
}

// issueSessionCookie builds the signed session token for an allowed email.
func (c *Config) issueSessionCookie(email string, now time.Time) string {
	payload := email + "|" + strconv.FormatInt(now.Add(sessionTTL).Unix(), 10)
	return signToken(c.cookieKey, payload)
}

// validSession reports whether the visitor's Cookie header carries a valid,
// unexpired, allow-listed session.
func (c *Config) validSession(cookieHeader string, now time.Time) bool {
	tok := readCookie(cookieHeader, cookieName)
	if tok == "" {
		return false
	}
	payload, ok := verifyToken(c.cookieKey, tok)
	if !ok {
		return false
	}
	email, expStr, found := strings.Cut(payload, "|")
	if !found {
		return false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || now.Unix() >= exp {
		return false
	}
	// Re-check the allow-list on every request so revoking an email/domain in
	// the policy takes effect without waiting for the cookie to expire.
	return c.emailAllowed(email)
}

// issueState signs the original request path into the OAuth state parameter
// (CSRF protection + post-login redirect target), valid for stateTTL.
func (c *Config) issueState(origPath string, now time.Time) string {
	if origPath == "" || origPath == CallbackPath {
		origPath = "/"
	}
	payload := origPath + "|" + strconv.FormatInt(now.Add(stateTTL).Unix(), 10)
	return signToken(c.cookieKey, payload)
}

// verifyState validates the state and returns the original path to redirect to.
func (c *Config) verifyState(state string, now time.Time) (string, bool) {
	payload, ok := verifyToken(c.cookieKey, state)
	if !ok {
		return "", false
	}
	origPath, expStr, found := strings.Cut(payload, "|")
	if !found {
		return "", false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || now.Unix() >= exp {
		return "", false
	}
	if origPath == "" {
		origPath = "/"
	}
	return origPath, true
}

// readCookie extracts one cookie value from a raw Cookie header.
func readCookie(header, name string) string {
	for _, part := range strings.Split(header, ";") {
		part = strings.TrimSpace(part)
		if v, ok := strings.CutPrefix(part, name+"="); ok {
			return v
		}
	}
	return ""
}
