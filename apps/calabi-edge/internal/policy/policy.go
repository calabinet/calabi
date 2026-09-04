// Package policy parses a tunnel's server-authoritative security policy out
// of its config_json blob and evaluates it against a visitor connection.
//
// Source of truth: tunnel-svc's config_json (set via the console, returned to
// the edge in the ClaimTunnel response). The edge — NOT the daemon — parses
// and enforces it at the listener accept path, so a tampered client cannot
// strip its own restrictions.
//
// Fail-open contract: a malformed config_json yields a nil Policy (allow all)
// — we never break legitimate traffic because of our own parse error. The
// authoritative validation lives at the WRITE path (bff-console rejects bad
// CIDRs on save); Parse here is the lenient read side.
//
// This file holds the always-present access-control features: IP access control
// (allow/deny CIDR) and HTTP Basic auth. The optional advanced features
// (connection rate limiting, request-header rewriting, an OAuth login wall) sit
// behind the `adv` seam — see parseAdvanced and the Has*/Allow* methods.
package policy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

// Policy is the parsed, ready-to-evaluate per-tunnel security policy. A nil
// *Policy means "no policy" (allow everything). Construct via Parse.
type Policy struct {
	// IPAllow, when non-empty, switches IP access to allowlist mode: a
	// visitor is permitted only if its source IP falls in one of these nets.
	IPAllow []*net.IPNet
	// IPDeny is always evaluated first and wins over IPAllow: a source IP in
	// any deny net is rejected even if it also matches an allow net.
	IPDeny []*net.IPNet
	// BasicAuth, when non-nil, requires HTTP Basic credentials on every
	// request (HTTP/HTTPS tunnels only — the edge must terminate + parse). nil
	// = no auth requirement.
	BasicAuth *BasicAuth
	// adv carries the advanced features (rate limit / header rewrite / OAuth).
	// The `advanced` type and the Has*/Allow* methods are build-tagged; where
	// those features aren't built it is an empty struct and the methods report
	// "off" / pass through.
	adv advanced
}

// BasicAuth is the parsed HTTP Basic auth requirement for a tunnel.
type BasicAuth struct {
	// users maps username → bcrypt hash. bff-console hashes the plaintext
	// password on save, so the edge only ever sees hashes (config_json that
	// flows through the control plane never carries a cleartext password).
	users map[string]string
	// okCache memoizes verified-good Authorization header values so repeated
	// requests from an authenticated client (a browser re-sends the header on
	// every asset) skip the deliberately-slow bcrypt compare. Bounded by the
	// number of valid credentials (≈ user count) and reset on each policy
	// hot-update (a fresh BasicAuth is parsed). Only SUCCESSES are cached —
	// wrong credentials always pay the bcrypt cost, which rate-limits brute
	// force. Keyed by the base64 credential token.
	okCache sync.Map
}

// rawConfig mirrors the slice of config_json this file parses (IP + Basic
// auth). Unknown keys are ignored by encoding/json, so the advanced blocks
// (rate_limit / request_headers / oauth), parsed separately in
// parseAdvanced, don't appear here and a self-hosted edge silently ignores them.
type rawConfig struct {
	Security struct {
		IP struct {
			Allow []string `json:"allow"`
			Deny  []string `json:"deny"`
		} `json:"ip"`
		BasicAuth struct {
			Users []rawBasicUser `json:"users"`
		} `json:"basic_auth"`
	} `json:"security"`
}

type rawBasicUser struct {
	User string `json:"user"`
	Hash string `json:"hash"`
}

// Parse extracts the security policy from a tunnel's config_json.
//
// Returns (nil, nil) when there is no actionable policy (empty blob, or a
// security block with no rules) — callers treat nil as allow-all. Returns
// (nil, err) only when config_json itself is not valid JSON; the caller should
// log and fall back to allow-all (fail-open). Individual malformed CIDR /
// IP entries are skipped (they were already rejected at the write path); a
// skipped allow entry only ever makes the policy MORE restrictive, never less.
func Parse(configJSON string) (*Policy, error) {
	s := strings.TrimSpace(configJSON)
	if s == "" || s == "{}" {
		return nil, nil
	}
	var raw rawConfig
	if err := json.Unmarshal([]byte(s), &raw); err != nil {
		return nil, fmt.Errorf("policy: parse config_json: %w", err)
	}
	p := &Policy{
		IPAllow:   parseNets(raw.Security.IP.Allow),
		IPDeny:    parseNets(raw.Security.IP.Deny),
		BasicAuth: parseBasicAuth(raw.Security.BasicAuth.Users),
	}
	// parseAdvanced populates the rate-limit / header-rewrite / OAuth features
	// where they are built, and reports whether any was actionable.
	advActionable := p.parseAdvanced(s)
	if len(p.IPAllow) == 0 && len(p.IPDeny) == 0 && p.BasicAuth == nil && !advActionable {
		return nil, nil // valid JSON but no actionable rules → no policy
	}
	return p, nil
}

// parseBasicAuth builds the user→hash map, skipping entries missing a username
// or hash. Returns nil when no usable credentials remain (= no auth required).
func parseBasicAuth(users []rawBasicUser) *BasicAuth {
	if len(users) == 0 {
		return nil
	}
	m := make(map[string]string, len(users))
	for _, u := range users {
		name := strings.TrimSpace(u.User)
		hash := strings.TrimSpace(u.Hash)
		if name == "" || hash == "" {
			continue
		}
		m[name] = hash
	}
	if len(m) == 0 {
		return nil
	}
	return &BasicAuth{users: m}
}

// HasBasicAuth reports whether the policy requires HTTP Basic credentials.
func (p *Policy) HasBasicAuth() bool {
	return p != nil && p.BasicAuth != nil && len(p.BasicAuth.users) > 0
}

// CheckBasicAuth reports whether the Authorization header value satisfies the
// tunnel's Basic auth. authValue is the raw header value (e.g. "Basic <b64>").
// No requirement (nil receiver / no users) = allow. Verified credentials are
// memoized so a browser re-sending the header on every asset doesn't re-pay
// the bcrypt cost.
func (p *Policy) CheckBasicAuth(authValue string) bool {
	if !p.HasBasicAuth() {
		return true
	}
	b := p.BasicAuth
	const prefix = "Basic "
	if len(authValue) <= len(prefix) || !strings.EqualFold(authValue[:len(prefix)], prefix) {
		return false
	}
	enc := strings.TrimSpace(authValue[len(prefix):])
	if _, ok := b.okCache.Load(enc); ok {
		return true
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return false
	}
	user, pass, ok := strings.Cut(string(raw), ":")
	if !ok {
		return false
	}
	hash, ok := b.users[user]
	if !ok {
		return false
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)) != nil {
		return false
	}
	b.okCache.Store(enc, struct{}{})
	return true
}

// parseNets turns a list of CIDR or bare-IP strings into IPNets, skipping any
// entry that doesn't parse. A bare IP ("203.0.113.7") is treated as a host
// route (/32 for v4, /128 for v6) so users don't have to append the mask.
func parseNets(in []string) []*net.IPNet {
	if len(in) == 0 {
		return nil
	}
	out := make([]*net.IPNet, 0, len(in))
	for _, raw := range in {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(raw); err == nil {
			out = append(out, n)
			continue
		}
		// Bare IP → host route.
		if ip := net.ParseIP(raw); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
		// else: silently skip (write path validates; read path stays lenient).
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// EvaluateIP reports whether a visitor with source IP ip is allowed by the
// policy. Semantics:
//   - nil policy            → allow (no policy configured).
//   - ip in any deny net    → deny (deny wins over allow).
//   - allow list non-empty  → allow only if ip matches an allow net.
//   - allow list empty       → allow (deny-only mode).
//
// An unparseable / nil ip naturally fails allowlist matching, so when an allow
// list is configured an unknown source is denied (correct restrictive default
// for "only these IPs"); with no allow list it is allowed.
func (p *Policy) EvaluateIP(ip net.IP) bool {
	if p == nil {
		return true
	}
	for _, n := range p.IPDeny {
		if n.Contains(ip) {
			return false
		}
	}
	if len(p.IPAllow) == 0 {
		return true
	}
	for _, n := range p.IPAllow {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// AllowIPString is a listener-friendly wrapper: it parses a bare IP string
// (what the edge's extractIP helpers already produce) and evaluates it. An
// unparseable string is treated as a nil IP (see EvaluateIP).
func (p *Policy) AllowIPString(ipStr string) bool {
	if p == nil {
		return true
	}
	return p.EvaluateIP(net.ParseIP(strings.TrimSpace(ipStr)))
}

// HasIPRules reports whether the policy actually constrains source IPs. Lets a
// listener skip the per-connection check entirely for the common (no-policy)
// case without a nil dance.
func (p *Policy) HasIPRules() bool {
	return p != nil && (len(p.IPAllow) > 0 || len(p.IPDeny) > 0)
}
