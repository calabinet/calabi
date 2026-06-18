// security_flags.go — CLI flags that attach a per-tunnel security policy to a
// `calabi http|tcp|udp|sni` run. The flags build a config_json `security` block
// (the same shape the console writes) which the client sends to the edge in
// NEW_PROXY (ProxyOptions.security_config_json).
//
// IMPORTANT: this policy only takes effect against a STANDALONE / self-hosted
// edge (one running with `mode: standalone` / CALABI_EDGE_MODE=standalone and no
// control plane wired). A managed or BYOI edge IGNORES client-supplied policy —
// there, access control is configured via the web console and gated per plan.
// Unless the client is in standalone mode (`calabi mode standalone` /
// CALABI_MODE=standalone) or the caller passes --standalone, we print a one-line
// hint to stderr so a managed-platform user isn't lulled into thinking the
// tunnel is protected.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// stringList is a flag.Value accumulating one entry per occurrence — repeat the
// flag for multiple values (`--ip-allow a --ip-allow b`). We deliberately do
// NOT comma-split: header values, passwords, and OAuth secrets can contain
// commas, and splitting them would silently corrupt the policy.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	if t := strings.TrimSpace(v); t != "" {
		*s = append(*s, t)
	}
	return nil
}

// securityFlags collects the raw CLI inputs for one tunnel's policy.
type securityFlags struct {
	l7         bool
	file       string
	standalone bool // declared self-hosted target → suppress the managed-edge warning

	ipAllow stringList
	ipDeny  stringList
	rate    int

	basicAuth         stringList
	setHeader         stringList
	delHeader         stringList
	oauthProvider     string
	oauthClientID     string
	oauthClientSecret string
	oauthEmail        stringList
	oauthDomain       stringList
}

// registerSecurityFlags wires the policy flags onto fs. l7=true adds the
// HTTP-only knobs (basic-auth / headers / oauth); L4 tunnels (tcp/udp/sni) get
// IP only. It returns the collector plus the value-flag names to feed
// reorderArgs so the flags parse even when typed after the positional port.
//
// IP allow/deny and HTTP Basic auth are always available. The advanced knobs
// (--rate / --set-header / --del-header / --oauth-*) are wired by
// registerAdvancedFlags and folded in by applyAdvanced, which are build-tagged.
func registerSecurityFlags(fs *flag.FlagSet, l7 bool) (*securityFlags, []string) {
	sf := &securityFlags{l7: l7}
	// Default follows the client mode (`calabi mode standalone` / CALABI_MODE);
	// the flag is a per-command override for a one-off standalone target.
	fs.BoolVar(&sf.standalone, "standalone", clientIsStandalone(),
		"declare the target edge is self-hosted (mode: standalone); suppresses the managed-edge warning")
	fs.Var(&sf.ipAllow, "ip-allow", "allowlist CIDR/IP (repeatable); only these may connect")
	fs.Var(&sf.ipDeny, "ip-deny", "denylist CIDR/IP (repeatable); always blocked, wins over allow")
	fs.StringVar(&sf.file, "security-file", "", `JSON file with a full {"security":{…}} block; flags merge on top`)
	names := []string{"ip-allow", "ip-deny", "security-file"}
	if l7 {
		fs.Var(&sf.basicAuth, "basic-auth", "HTTP Basic credential user:pass (repeatable; password is bcrypt-hashed locally)")
		names = append(names, "basic-auth")
	}
	sf.registerAdvancedFlags(fs, &names)
	return sf, names
}

// --- config_json `security` block, mirroring policy.rawConfig on the edge ----

type secIP struct {
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
}
type secUser struct {
	User string `json:"user"`
	Hash string `json:"hash"`
}
type secBasicAuth struct {
	Users []secUser `json:"users"`
}
type secRate struct {
	PerMinute int `json:"per_minute"`
}
type secHeaders struct {
	Set    map[string]string `json:"set,omitempty"`
	Remove []string          `json:"remove,omitempty"`
}
type secOAuth struct {
	Provider     string   `json:"provider"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	AllowEmails  []string `json:"allow_emails,omitempty"`
	AllowDomains []string `json:"allow_domains,omitempty"`
}
type secBlock struct {
	IP             *secIP        `json:"ip,omitempty"`
	BasicAuth      *secBasicAuth `json:"basic_auth,omitempty"`
	RateLimit      *secRate      `json:"rate_limit,omitempty"`
	RequestHeaders *secHeaders   `json:"request_headers,omitempty"`
	OAuth          *secOAuth     `json:"oauth,omitempty"`
}
type secEnvelope struct {
	Security secBlock `json:"security"`
}

// buildConfigJSON turns the parsed flags (and optional --security-file base)
// into a `{"security":{…}}` string, or "" when nothing was configured. The
// password in --basic-auth is bcrypt-hashed here so the blob the edge receives
// carries only hashes — identical to what bff-console stores.
func (sf *securityFlags) buildConfigJSON() (string, error) {
	var env secEnvelope
	if sf.file != "" {
		raw, err := os.ReadFile(sf.file)
		if err != nil {
			return "", fmt.Errorf("read --security-file: %w", err)
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			return "", fmt.Errorf(`parse --security-file (want {"security":{…}}): %w`, err)
		}
	}
	sec := &env.Security

	if len(sf.ipAllow) > 0 || len(sf.ipDeny) > 0 {
		if sec.IP == nil {
			sec.IP = &secIP{}
		}
		sec.IP.Allow = append(sec.IP.Allow, sf.ipAllow...)
		sec.IP.Deny = append(sec.IP.Deny, sf.ipDeny...)
	}

	if len(sf.basicAuth) > 0 {
		if sec.BasicAuth == nil {
			sec.BasicAuth = &secBasicAuth{}
		}
		for _, pair := range sf.basicAuth {
			user, pass, ok := strings.Cut(pair, ":")
			user = strings.TrimSpace(user)
			if !ok || user == "" || pass == "" {
				return "", fmt.Errorf("--basic-auth %q: want user:pass", pair)
			}
			hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
			if err != nil {
				return "", fmt.Errorf("--basic-auth %q: hash password: %w", user, err)
			}
			sec.BasicAuth.Users = append(sec.BasicAuth.Users, secUser{User: user, Hash: string(hash)})
		}
	}

	// Advanced features (rate limit / header rewrite / OAuth): applyAdvanced
	// folds them in from the flags where supported, or strips them (including any
	// from --security-file) where not. Build-tagged.
	if err := sf.applyAdvanced(sec); err != nil {
		return "", err
	}

	if sec.IP == nil && sec.BasicAuth == nil && sec.RateLimit == nil &&
		sec.RequestHeaders == nil && sec.OAuth == nil {
		return "", nil
	}
	out, err := json.Marshal(&env)
	if err != nil {
		return "", err
	}
	// Footgun guard: a managed / BYOI edge silently ignores this. Warn so the
	// user doesn't assume protection they won't get — unless they passed
	// --standalone (or CALABI_STANDALONE=1) to declare a self-hosted target.
	if !sf.standalone {
		fmt.Fprintln(os.Stderr,
			"note: security flags only take effect on a self-hosted (mode: standalone) edge; "+
				"the managed platform configures access control via the web console. "+
				"Run `calabi mode standalone` (or pass --standalone) to silence this if your edge is self-hosted.")
	}
	return string(out), nil
}
