// security_flags.go — CLI flags that attach a per-tunnel security policy to a
// `calabi http|tcp|udp|sni` run. The flags build a config_json `security` block
// (the same shape the console writes) which the client sends to the edge in
// NEW_PROXY (ProxyOptions.security_config_json).
//
// WHERE EACH PART TAKES EFFECT. The IP rules (--ip-allow / --ip-deny) work
// everywhere: a managed edge relays them to the control plane, which keeps just
// the addresses, revalidates them, and writes them onto the tunnel row. The L7
// knobs — --basic-auth, --rate, --set-header, --del-header, --oauth-* — still
// only apply on a STANDALONE / self-hosted edge; on the managed platform those
// are configured in the web console and gated per plan, because a client that
// could mint its own credentials could mint whatever it liked.
//
// That split is why the note is conditional on what was actually passed. It
// used to fire for any policy at all and say the whole lot was ignored — which
// was true when Persist did not forward anything, and became a lie about the IP
// flags the moment it did. A footgun warning that is wrong is worse than none:
// it teaches people to ignore the next one.
//
// WHO DECIDES, AND WHO GETS TO SAY SO. The note now fires on the EDGE's answer
// (NEW_PROXY_RESP.client_policy), not on `--standalone` / `calabi mode
// standalone`. Those are client-side declarations, and whether a policy is
// honoured is decided edge-side — standalone mode AND no control plane wired.
// A BYOI edge is standalone in spirit and control-plane-wired in fact, so it
// drops the L7 half; declaring standalone used to SILENCE the note about
// exactly that, which is how a tunnel everybody believed had a password turned
// out to have none. A flag may not silence a fact it has no part in deciding.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"

	proto "github.com/calabinet/calabi/pkg/protocol"
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

	ipAllow   stringList
	ipDeny    stringList
	rate      int
	ratePerIP int

	// l7Proposed names the L7 knobs this run actually passed, in the flag
	// spelling the user typed. Filled by buildConfigJSON, read by
	// NoteEdgePolicy once the edge has said what it did with them.
	l7Proposed []string

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
// IP only.
//
// It used to also return the value-flag names for reorderArgs. It no longer
// needs to: reorderArgs reads them off the FlagSet. A returned list is a second
// place to remember, and a list that is merely INCOMPLETE fails quietly — the
// unlisted flag swallows the next token as its value.
//
// IP allow/deny and HTTP Basic auth are always available. The advanced knobs
// (--rate / --set-header / --del-header / --oauth-*) are wired by
// registerAdvancedFlags and folded in by applyAdvanced, which are build-tagged.
func registerSecurityFlags(fs *flag.FlagSet, l7 bool) *securityFlags {
	sf := &securityFlags{l7: l7}
	// Default follows the client mode (`calabi mode standalone` / CALABI_MODE);
	// the flag is a per-command override for a one-off standalone target.
	fs.BoolVar(&sf.standalone, "standalone", clientIsStandalone(),
		"declare the target edge is self-hosted (mode: standalone). Only affects the "+
			"footgun note, and only against an edge too old to report what it did — a "+
			"current edge's own answer wins over this either way")
	fs.Var(&sf.ipAllow, "ip-allow", "allowlist CIDR/IP (repeatable); only these may connect")
	fs.Var(&sf.ipDeny, "ip-deny", "denylist CIDR/IP (repeatable); always blocked, wins over allow")
	fs.StringVar(&sf.file, "security-file", "", `JSON file with a full {"security":{…}} block; flags merge on top`)
	if l7 {
		fs.Var(&sf.basicAuth, "basic-auth", "HTTP Basic credential user:pass (repeatable; password is bcrypt-hashed locally)")
	}
	sf.registerAdvancedFlags(fs)
	return sf
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
	PerMinute int `json:"per_minute,omitempty"`
	// PerIPPerMinute caps a single visitor address. omitempty on both so a
	// tunnel that sets only one does not ship a zero the edge would have to
	// read as "unlimited" by convention rather than by absence.
	PerIPPerMinute int `json:"per_ip_per_minute,omitempty"`
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
	// Remember which L7 knobs were passed; the note itself waits for the edge's
	// answer (NoteEdgePolicy). Nothing is printed here — at this point all we
	// know is what the user typed, and the question is what the edge does.
	sf.l7Proposed = managedEdgeIgnores(sec)
	return string(out), nil
}

// NoteEdgePolicy prints the footgun note, once the edge has said what it did
// with the policy we sent. Call it right after a successful registration.
//
//	applied  — the edge put the whole blob into effect. Say nothing.
//	relayed  — the edge does not apply client policy: the control plane keeps
//	           the IP rules and drops the L7 ones. Say so, naming them.
//	""       — nothing was offered, or the edge is too old to answer. Fall back
//	           to the old local guess, which is the best an old edge allows.
//
// The fallback still honours --standalone, and that is the one place it still
// can: an edge that never answers tells us nothing to override the guess with.
func (sf *securityFlags) NoteEdgePolicy(result proto.ClientPolicyResult) {
	if len(sf.l7Proposed) == 0 || result == proto.ClientPolicyApplied {
		return
	}
	if result == "" && sf.standalone {
		return // old edge + declared standalone: no better answer available
	}
	fmt.Fprintln(os.Stderr,
		"note: "+strings.Join(sf.l7Proposed, ", ")+" were NOT applied — this edge does not "+
			"accept client-supplied policy (it is not standalone, or it is wired to a control "+
			"plane, which a self-hosted/BYOI edge is). Your IP rules were applied. Configure "+
			"these in the web console instead; until you do, this tunnel has none of them.")
}

// managedEdgeIgnores names the parts of a policy a managed edge will not apply,
// in the flag spelling the user typed.
func managedEdgeIgnores(sec *secBlock) []string {
	var out []string
	if sec.BasicAuth != nil {
		out = append(out, "--basic-auth")
	}
	if sec.RateLimit != nil {
		out = append(out, "--rate / --rate-per-ip")
	}
	if sec.RequestHeaders != nil {
		out = append(out, "--set-header / --del-header")
	}
	if sec.OAuth != nil {
		out = append(out, "--oauth-*")
	}
	return out
}
