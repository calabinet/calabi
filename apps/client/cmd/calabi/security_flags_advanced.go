package main

// security_flags_advanced.go — the advanced (platform-only) per-tunnel policy
// knobs: connection rate limiting, request-header rewrite, and the OAuth login
// wall. These used to be platform-edition-only; they now ship in the single
// binary and apply to self-hosted edges too (full-oss-plan F1). Previously
// security_flags_community.go stubbed them out,
// whose registerAdvancedFlags registers nothing and whose applyAdvanced strips
// these blocks. IP allow/deny + HTTP Basic auth live in security_flags.go and
// are present in every edition.

import (
	"flag"
	"fmt"
	"strings"
)

// registerAdvancedFlags wires --rate (all tunnel types) plus the HTTP-only
// --set-header / --del-header / --oauth-* knobs (l7), appending their names so
// reorderArgs accepts them after the positional port.
func (sf *securityFlags) registerAdvancedFlags(fs *flag.FlagSet, names *[]string) {
	fs.IntVar(&sf.rate, "rate", 0, "max NEW connections per minute (0 = unlimited)")
	*names = append(*names, "rate")
	if sf.l7 {
		fs.Var(&sf.setHeader, "set-header", `set/replace an upstream request header "Name: Value" (repeatable)`)
		fs.Var(&sf.delHeader, "del-header", "strip an upstream request header by name (repeatable)")
		fs.StringVar(&sf.oauthProvider, "oauth-provider", "", "OAuth login-wall provider: google | github")
		fs.StringVar(&sf.oauthClientID, "oauth-client-id", "", "OAuth client id")
		fs.StringVar(&sf.oauthClientSecret, "oauth-client-secret", "", "OAuth client secret")
		fs.Var(&sf.oauthEmail, "oauth-allow-email", "OAuth: allowed email address (repeatable; empty = any)")
		fs.Var(&sf.oauthDomain, "oauth-allow-domain", "OAuth: allowed email domain (repeatable; empty = any)")
		*names = append(*names, "set-header", "del-header",
			"oauth-provider", "oauth-client-id", "oauth-client-secret",
			"oauth-allow-email", "oauth-allow-domain")
	}
}

// applyAdvanced folds the rate-limit / header-rewrite / OAuth flags into the
// security block (on top of anything from --security-file).
func (sf *securityFlags) applyAdvanced(sec *secBlock) error {
	switch {
	case sf.rate > 0:
		sec.RateLimit = &secRate{PerMinute: sf.rate}
	case sf.rate < 0:
		return fmt.Errorf("--rate must be >= 0")
	}

	if len(sf.setHeader) > 0 || len(sf.delHeader) > 0 {
		if sec.RequestHeaders == nil {
			sec.RequestHeaders = &secHeaders{}
		}
		for _, kv := range sf.setHeader {
			name, val, ok := strings.Cut(kv, ":")
			name = strings.TrimSpace(name)
			if !ok || name == "" {
				return fmt.Errorf(`--set-header %q: want "Name: Value"`, kv)
			}
			if sec.RequestHeaders.Set == nil {
				sec.RequestHeaders.Set = map[string]string{}
			}
			sec.RequestHeaders.Set[name] = strings.TrimSpace(val)
		}
		sec.RequestHeaders.Remove = append(sec.RequestHeaders.Remove, sf.delHeader...)
	}

	if p := strings.TrimSpace(sf.oauthProvider); p != "" {
		if sf.oauthClientID == "" || sf.oauthClientSecret == "" {
			return fmt.Errorf("--oauth-provider requires --oauth-client-id and --oauth-client-secret")
		}
		sec.OAuth = &secOAuth{
			Provider:     p,
			ClientID:     sf.oauthClientID,
			ClientSecret: sf.oauthClientSecret,
			AllowEmails:  sf.oauthEmail,
			AllowDomains: sf.oauthDomain,
		}
	}
	return nil
}
