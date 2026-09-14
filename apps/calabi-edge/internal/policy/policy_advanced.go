package policy

// policy_advanced.go — the advanced (platform-only) access-control features:
// per-tunnel connection rate limiting, request-header rewriting, and OAuth
// authentication.
//
// These used to be platform-only, stubbed out to "off"/passthrough by a
// self-hosted-build twin. Since F3 there is no such split: one edge binary
// ships and a self-hosted edge enforces the same policy set as a managed one.
// On the hosted product these are gated by PLAN, and that gate lives in the
// control plane (tunnel-svc), not here.

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
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
	// perIP, when non-nil, additionally caps each VISITOR ADDRESS. Opt-in, and
	// separate from rateLimiter, which stays the aggregate ceiling: with only
	// the shared bucket, a tunnel rate limit is also the lever an abuser pulls
	// — whoever arrives fastest drains it and every other visitor gets 429.
	perIP *perIPLimiter
	// reqHeaders, when non-nil, rewrites each HTTP/HTTPS request's headers
	// before forwarding upstream (set/replace + remove). nil = no rewrite.
	reqHeaders *headerRewrite
	// oauthCfg, when non-nil, gates HTTP/HTTPS visitors behind an identity
	// provider login (Google / GitHub). nil = no OAuth authentication.
	oauthCfg *oauth.Config
	// oauthRef is the ORG LOGIN POLICY this tunnel points at, when it points
	// at one. Its client secret is deliberately not in config_json — it lives
	// once, in the control plane — so a policy carrying a ref is INCOMPLETE
	// until ResolveOAuthSecret supplies it. See NeedsOAuthSecret.
	oauthRef string
	// oauthPending holds the non-secret half while the secret is outstanding,
	// so resolving is one call rather than a re-parse.
	oauthPending *pendingOAuth
	// oauthSecret is what was resolved, kept so it can be carried across a
	// hot-swap: a config-svc delta rebuilds the policy from a blob that has no
	// secret in it.
	oauthSecret string
}

// rawAdvanced mirrors the config_json blocks parsed here. It overlaps
// rawConfig only in the `security` wrapper; encoding/json ignores the ip /
// basic_auth keys handled in policy.go.
type rawAdvanced struct {
	Security struct {
		RateLimit struct {
			PerMinute int64 `json:"per_minute"`
			// PerIPPerMinute caps a single visitor address. Deliberately a new
			// key rather than a reinterpretation of PerMinute: reading a
			// shipped number as per-IP would multiply every configured limit by
			// the number of visitors, and the first sign of it would be the
			// upstream falling over.
			PerIPPerMinute int64 `json:"per_ip_per_minute"`
		} `json:"rate_limit"`
		RequestHeaders struct {
			Set    map[string]string `json:"set"`
			Remove []string          `json:"remove"`
		} `json:"request_headers"`
		OAuth struct {
			// FromPolicy names an ORG login policy. When set, the secret is
			// NOT here — tunnel-svc expands everything but the credential.
			FromPolicy   string   `json:"from_policy"`
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
	p.adv.perIP = buildPerIPLimiter(raw.Security.RateLimit.PerIPPerMinute)
	p.adv.reqHeaders = parseRequestHeaders(raw.Security.RequestHeaders.Set, raw.Security.RequestHeaders.Remove)
	p.adv.oauthRef = strings.TrimSpace(raw.Security.OAuth.FromPolicy)
	if p.adv.oauthRef != "" && strings.TrimSpace(raw.Security.OAuth.ClientSecret) == "" {
		// Referencing a policy and carrying no secret: park the non-secret half
		// and wait. Building an oauth.Config here would fail (it requires a
		// credential) and the tunnel would serve with no login — which is how a
		// console edit to an unrelated field used to switch SSO off.
		p.adv.oauthPending = &pendingOAuth{
			provider: raw.Security.OAuth.Provider,
			clientID: raw.Security.OAuth.ClientID,
			emails:   raw.Security.OAuth.AllowEmails,
			domains:  raw.Security.OAuth.AllowDomains,
		}
	} else {
		p.adv.oauthCfg = parseOAuth(raw.Security.OAuth.Provider, raw.Security.OAuth.ClientID,
			raw.Security.OAuth.ClientSecret, raw.Security.OAuth.AllowEmails, raw.Security.OAuth.AllowDomains)
	}
	return p.adv.rateLimiter != nil || p.adv.perIP != nil ||
		p.adv.reqHeaders != nil || p.adv.oauthCfg != nil || p.adv.oauthPending != nil
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
	lim, burst := rateAndBurst(perMin)
	return rate.NewLimiter(lim, burst)
}

// rateAndBurst turns a per-minute cap into token-bucket terms: events/sec =
// perMin/60, burst = perMin/6 (about 10s of budget) with a floor so a browser
// opening a clump of parallel connections is not nuisance-rejected.
func rateAndBurst(perMin int64) (rate.Limit, int) {
	burst := int(perMin / 6)
	if burst < 10 {
		burst = 10
	}
	return rate.Limit(float64(perMin) / 60.0), burst
}

// HasRateLimit reports whether the policy caps this tunnel connection rate AT
// ALL — aggregate or per-visitor.
//
// Both, because every listener guards the call as
// `if pol.HasRateLimit() && !pol.AllowRate(ip)`: a tunnel that configured only
// a per-IP cap would otherwise never reach AllowRate, and the limit it asked
// for would silently not exist.
func (p *Policy) HasRateLimit() bool {
	return p != nil && (p.adv.rateLimiter != nil || p.adv.perIP != nil)
}

// maxPerIPBuckets caps how many visitor addresses ONE TUNNEL tracks.
//
// The map is keyed by attacker-controlled input, so the map is the
// vulnerability: uncapped, a flood of rotated or spoofed sources turns a
// protective feature into a memory-exhaustion vector. Two generations are kept
// (see perIPLimiter), so the real ceiling is twice this.
const maxPerIPBuckets = 4096

// perIPLimiter is a bounded set of token buckets keyed by visitor address.
//
// Eviction is a two-generation clock rather than a true LRU: when `cur` fills
// it becomes `prev` and a fresh map takes over, and a lookup that hits `prev`
// promotes the bucket. Idle addresses age out within two rotations, with no
// per-entry bookkeeping on the accept path. A real LRU would cost a list
// update per visitor connection to make eviction marginally fairer — and the
// thing being evicted is a rate-limit bucket, where losing one means a visitor
// gets a fresh allowance.
//
// Note what eviction means against an attacker rotating source addresses: each
// new address starts with a full burst. That is inherent to per-IP limiting,
// and it is exactly why the tunnel-wide bucket stays — it is the backstop a
// rotating flood still has to get past.
//
// One mutex per tunnel, held for a map lookup on the accept path. Next to what
// an accept already costs (syscalls, TLS, an upstream dial) that is noise, and
// a lock-free scheme would still have to solve rotation.
type perIPLimiter struct {
	lim   rate.Limit
	burst int

	mu   sync.Mutex
	cur  map[string]*rate.Limiter
	prev map[string]*rate.Limiter
}

func buildPerIPLimiter(perMin int64) *perIPLimiter {
	if perMin <= 0 {
		return nil
	}
	lim, burst := rateAndBurst(perMin)
	return &perIPLimiter{lim: lim, burst: burst, cur: make(map[string]*rate.Limiter)}
}

// allow consumes one token from this address bucket.
//
// An address we could not read shares the empty-string bucket with every other
// unattributable visitor. That is worse for those visitors than having their
// own — which is the right way round: an unreadable address must not become a
// way to skip the limit.
func (l *perIPLimiter) allow(ip string) bool {
	l.mu.Lock()
	b, ok := l.cur[ip]
	if !ok {
		if b, ok = l.prev[ip]; ok {
			l.cur[ip] = b // promote: in use again
		} else {
			if len(l.cur) >= maxPerIPBuckets {
				l.prev, l.cur = l.cur, make(map[string]*rate.Limiter)
			}
			b = rate.NewLimiter(l.lim, l.burst)
			l.cur[ip] = b
		}
	}
	l.mu.Unlock()
	return b.Allow()
}

func (l *perIPLimiter) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.cur) + len(l.prev)
}

// HasPerIPRateLimit reports whether the policy caps any single visitor.
func (p *Policy) HasPerIPRateLimit() bool { return p != nil && p.adv.perIP != nil }

// perIPBucketCount is how many addresses are currently tracked. Test-facing.
func (p *Policy) perIPBucketCount() int {
	if p == nil || p.adv.perIP == nil {
		return 0
	}
	return p.adv.perIP.count()
}

// AllowRate consumes one token for this visitor, returning false when either
// bucket is drained (caller sheds: 429 / close / drop). No limiter = allowed.
//
// PER-IP IS CHECKED FIRST, and a rejection there returns without touching the
// tunnel-wide bucket. Charging the aggregate for a connection that was already
// refused would let an abuser drain it through the very gate that stopped them,
// which is the bug this pair exists to fix.
func (p *Policy) AllowRate(visitorIP string) bool {
	if p == nil {
		return true
	}
	if p.adv.perIP != nil && !p.adv.perIP.allow(visitorIP) {
		return false
	}
	if p.adv.rateLimiter == nil {
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

// ---- OAuth authentication ----------------------------------------------------

// parseOAuth builds the OAuth authentication config, or nil when not configured.
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

// pendingOAuth is the non-secret half of a login that is waiting for its
// credential.
type pendingOAuth struct {
	provider string
	clientID string
	emails   []string
	domains  []string
}

// OAuthPolicyRef is the org login policy this tunnel references, or "".
func (p *Policy) OAuthPolicyRef() string {
	if p == nil {
		return ""
	}
	return p.adv.oauthRef
}

// NeedsOAuthSecret reports that this policy names a login it cannot yet perform.
//
// The caller MUST act on it. A policy in this state has no OAuth gate at all,
// so treating it as "no login configured" serves the tunnel to everybody — the
// failure is open, silent, and looks exactly like a tunnel that was never meant
// to have a login.
func (p *Policy) NeedsOAuthSecret() bool {
	return p != nil && p.adv.oauthPending != nil
}

// OAuthSecret returns the resolved credential, for carrying across a hot-swap.
func (p *Policy) OAuthSecret() string {
	if p == nil {
		return ""
	}
	return p.adv.oauthSecret
}

// ResolveOAuthSecret completes a policy that referenced an org login.
//
// An empty secret is an ERROR rather than a no-op: a caller whose control-plane
// fetch came back with nothing must not conclude it is finished and install a
// policy with no gate.
func (p *Policy) ResolveOAuthSecret(secret string) error {
	if p == nil {
		return errors.New("policy: nil")
	}
	if p.adv.oauthPending == nil {
		return nil // nothing was waiting
	}
	if strings.TrimSpace(secret) == "" {
		return errors.New("policy: empty oauth client secret")
	}
	pend := p.adv.oauthPending
	cfg, err := oauth.New(pend.provider, pend.clientID, secret, pend.emails, pend.domains)
	if err != nil {
		return err
	}
	p.adv.oauthCfg = cfg
	p.adv.oauthSecret = secret
	p.adv.oauthPending = nil
	return nil
}

// HasOAuth reports whether the policy gates visitors behind an OAuth login.
func (p *Policy) HasOAuth() bool {
	return p != nil && p.adv.oauthCfg != nil
}

// GateOAuth runs the OAuth authentication check for an HTTP/HTTPS visitor. It returns
// true when the edge already handled the request (wrote an IdP redirect /
// callback / error) — the caller must then NOT open the upstream. No OAuth
// configured (or nil policy) → false (pass through). Encapsulates the oauth
// package so the core listeners need no oauth import (the self-hosted build's
// stub returns false and pulls in nothing).
func (p *Policy) GateOAuth(w io.Writer, path, host string, https bool, cookie string, now time.Time) bool {
	if p == nil || p.adv.oauthCfg == nil {
		return false
	}
	ri := oauth.RequestInfo{Path: path, Host: host, HTTPS: https, Cookie: cookie}
	return p.adv.oauthCfg.Handle(w, ri, now) == oauth.Handled
}
