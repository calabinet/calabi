package policy

// policy_advanced.go — the advanced (platform-only) access-control features:
// per-tunnel connection rate limiting, request-header rewriting, and the OAuth
// login wall.
//
// These used to be platform-only, stubbed out to "off"/passthrough by a
// community-build twin. Since F3 there is no edition split: one edge binary
// ships and a self-hosted edge enforces the same policy set as a managed one.
// On the hosted product these are gated by PLAN, and that gate lives in the
// control plane (tunnel-svc), not here.

import (
	"encoding/json"
	"io"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/calabi/calabi/apps/calabi-edge/internal/oauth"
)

// advanced holds the platform-only policy features. nil sub-fields = feature
// off (the common case). Reached only via the methods below.
type advanced struct {
	// rateLimiter, when non-nil, caps the tunnel's NEW-connection rate (a
	// token bucket, all visitors share it — a per-tunnel ceiling that protects
	// the upstream from connection floods). nil = unlimited. For HTTP
	// keep-alive this is a connection-rate, not a per-request rate.
	rateLimiter *rate.Limiter
	// reqHeaders, when non-nil, rewrites each HTTP/HTTPS request's headers
	// before forwarding upstream (set/replace + remove). nil = no rewrite.
	reqHeaders *headerRewrite
	// oauthCfg, when non-nil, gates HTTP/HTTPS visitors behind an identity
	// provider login (Google / GitHub). nil = no login wall.
	oauthCfg *oauth.Config
}

// rawAdvanced mirrors the config_json blocks parsed here. It overlaps
// rawConfig only in the `security` wrapper; encoding/json ignores the ip /
// basic_auth keys handled in policy.go.
type rawAdvanced struct {
	Security struct {
		RateLimit struct {
			PerMinute int64 `json:"per_minute"`
		} `json:"rate_limit"`
		RequestHeaders struct {
			Set    map[string]string `json:"set"`
			Remove []string          `json:"remove"`
		} `json:"request_headers"`
		OAuth struct {
			Provider     string   `json:"provider"`
			ClientID     string   `json:"client_id"`
			ClientSecret string   `json:"client_secret"`
			AllowEmails  []string `json:"allow_emails"`
			AllowDomains []string `json:"allow_domains"`
		} `json:"oauth"`
	} `json:"security"`
}

// parseAdvanced populates the advanced features from config_json and reports
// whether any was actionable. Lenient: a JSON error (policy.go already
// validated the blob) or an individually-invalid block yields a nil feature,
// never an error.
func (p *Policy) parseAdvanced(configJSON string) bool {
	var raw rawAdvanced
	if err := json.Unmarshal([]byte(configJSON), &raw); err != nil {
		return false
	}
	p.adv.rateLimiter = buildRateLimiter(raw.Security.RateLimit.PerMinute)
	p.adv.reqHeaders = parseRequestHeaders(raw.Security.RequestHeaders.Set, raw.Security.RequestHeaders.Remove)
	p.adv.oauthCfg = parseOAuth(raw.Security.OAuth.Provider, raw.Security.OAuth.ClientID,
		raw.Security.OAuth.ClientSecret, raw.Security.OAuth.AllowEmails, raw.Security.OAuth.AllowDomains)
	return p.adv.rateLimiter != nil || p.adv.reqHeaders != nil || p.adv.oauthCfg != nil
}

// ---- Rate limit ----------------------------------------------------------

// buildRateLimiter constructs the per-tunnel new-connection token bucket, or
// nil for an unlimited (≤0) rate. Mirrors ratelimit.RateLimiter's sizing:
// events/sec = perMin/60, burst = perMin/6 with a small floor so a browser
// opening a clump of parallel connections isn't nuisance-rejected.
func buildRateLimiter(perMin int64) *rate.Limiter {
	if perMin <= 0 {
		return nil
	}
	burst := int(perMin / 6)
	if burst < 10 {
		burst = 10
	}
	return rate.NewLimiter(rate.Limit(float64(perMin)/60.0), burst)
}

// HasRateLimit reports whether the policy caps the tunnel's connection rate.
func (p *Policy) HasRateLimit() bool { return p != nil && p.adv.rateLimiter != nil }

// AllowRate consumes one token from the per-tunnel rate bucket, returning
// false when the bucket is drained (caller sheds: 429 / close / drop). No
// limiter = always allowed.
func (p *Policy) AllowRate() bool {
	if p == nil || p.adv.rateLimiter == nil {
		return true
	}
	return p.adv.rateLimiter.Allow()
}

// ---- Request-header rewrite ----------------------------------------------

// headerRewrite is the parsed per-tunnel request-header transform.
type headerRewrite struct {
	// set maps a lowercased header name → the canonical name + value to
	// inject (replacing any existing header of that name).
	set map[string]headerKV
	// remove is the set of lowercased header names to strip.
	remove map[string]bool
}

type headerKV struct {
	name  string
	value string
}

// parseRequestHeaders builds the request-header transform, dropping entries
// with an invalid name and stripping CR/LF from values (so a value can't smuggle
// in an extra header line). Returns nil when nothing actionable remains.
func parseRequestHeaders(set map[string]string, remove []string) *headerRewrite {
	hr := &headerRewrite{}
	if len(set) > 0 {
		hr.set = make(map[string]headerKV, len(set))
		for name, val := range set {
			name = strings.TrimSpace(name)
			lower := strings.ToLower(name)
			if !validHeaderName(name) || forbiddenRewriteHeader(lower) {
				continue
			}
			hr.set[lower] = headerKV{name: name, value: sanitizeHeaderValue(val)}
		}
	}
	if len(remove) > 0 {
		hr.remove = make(map[string]bool, len(remove))
		for _, name := range remove {
			lower := strings.ToLower(strings.TrimSpace(name))
			if lower == "" || forbiddenRewriteHeader(lower) {
				continue
			}
			hr.remove[lower] = true
		}
	}
	if len(hr.set) == 0 && len(hr.remove) == 0 {
		return nil
	}
	return hr
}

// forbiddenRewriteHeader bars framing / hop-by-hop headers from being set or
// removed — rewriting them (Content-Length, Transfer-Encoding, …) would
// desync the proxy's request framing and corrupt the keep-alive stream.
func forbiddenRewriteHeader(lower string) bool {
	switch lower {
	case "content-length", "transfer-encoding", "connection", "upgrade", "te", "trailer":
		return true
	}
	return false
}

// validHeaderName rejects empty names and any byte that can't appear in an
// HTTP token (whitespace, ':', controls) — defense against header injection.
func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r <= ' ' || r == ':' || r == 127 {
			return false
		}
	}
	return true
}

// sanitizeHeaderValue strips CR/LF so a configured value can't inject a
// second header line into the rewritten request.
func sanitizeHeaderValue(v string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(strings.TrimSpace(v))
}

// HasRequestHeaders reports whether the policy rewrites request headers.
func (p *Policy) HasRequestHeaders() bool {
	return p != nil && p.adv.reqHeaders != nil
}

// RewriteRequestHead applies the set/remove ops to a raw HTTP/1.1 request head
// (request line + header lines + blank terminator) and returns the modified
// head, normalized to CRLF. Header NAMES match case-insensitively; a `set`
// replaces an existing header in place (and drops duplicates), or is appended
// if absent. Malformed header lines are kept verbatim (fail-safe). No-op when
// the policy has no header rules.
func (p *Policy) RewriteRequestHead(head []byte) []byte {
	if !p.HasRequestHeaders() {
		return head
	}
	hr := p.adv.reqHeaders
	lines := strings.Split(string(head), "\n")
	if len(lines) == 0 {
		return head
	}
	var b strings.Builder
	b.WriteString(strings.TrimRight(lines[0], "\r")) // request line
	b.WriteString("\r\n")
	seen := make(map[string]bool)
	for _, ln := range lines[1:] {
		t := strings.TrimRight(ln, "\r")
		if t == "" {
			break // blank line → end of headers
		}
		colon := strings.IndexByte(t, ':')
		if colon <= 0 {
			b.WriteString(t) // malformed → keep verbatim
			b.WriteString("\r\n")
			continue
		}
		lower := strings.ToLower(strings.TrimSpace(t[:colon]))
		if hr.remove[lower] {
			continue
		}
		if kv, ok := hr.set[lower]; ok {
			if !seen[lower] {
				b.WriteString(kv.name)
				b.WriteString(": ")
				b.WriteString(kv.value)
				b.WriteString("\r\n")
				seen[lower] = true
			}
			continue // drop any further occurrences of a set header
		}
		b.WriteString(t)
		b.WriteString("\r\n")
	}
	for lower, kv := range hr.set {
		if !seen[lower] {
			b.WriteString(kv.name)
			b.WriteString(": ")
			b.WriteString(kv.value)
			b.WriteString("\r\n")
		}
	}
	b.WriteString("\r\n") // terminator
	return []byte(b.String())
}

// ---- OAuth login wall ----------------------------------------------------

// parseOAuth builds the OAuth login-wall config, or nil when not configured.
// An invalid config (bad provider / missing creds) fails OPEN to nil so a
// glitch never bricks the tunnel — bff-console validates at the write path.
func parseOAuth(provider, clientID, clientSecret string, allowEmails, allowDomains []string) *oauth.Config {
	if strings.TrimSpace(provider) == "" {
		return nil
	}
	c, err := oauth.New(provider, clientID, clientSecret, allowEmails, allowDomains)
	if err != nil {
		return nil
	}
	return c
}

// HasOAuth reports whether the policy gates visitors behind an OAuth login.
func (p *Policy) HasOAuth() bool {
	return p != nil && p.adv.oauthCfg != nil
}

// GateOAuth runs the OAuth login wall for an HTTP/HTTPS visitor. It returns
// true when the edge already handled the request (wrote an IdP redirect /
// callback / error) — the caller must then NOT open the upstream. No OAuth
// configured (or nil policy) → false (pass through). Encapsulates the oauth
// package so the core listeners need no oauth import (the community build's
// stub returns false and pulls in nothing).
func (p *Policy) GateOAuth(w io.Writer, path, host string, https bool, cookie string, now time.Time) bool {
	if p == nil || p.adv.oauthCfg == nil {
		return false
	}
	ri := oauth.RequestInfo{Path: path, Host: host, HTTPS: https, Cookie: cookie}
	return p.adv.oauthCfg.Handle(w, ri, now) == oauth.Handled
}
