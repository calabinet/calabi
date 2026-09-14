// oauth_policy_ref_test.go — a config that names an org login policy carries
// no secret, and the edge has to survive that.
//
// THE SHAPE. tunnel-svc expands an org OAuth policy PARTIALLY: provider,
// client_id and the allow lists land in config_json; the client secret stays in
// org_oauth_policies and the edge fetches it over its own authenticated
// connection. So `security.oauth` now arrives with everything except the one
// field oauth.New refuses to build without.
//
// THE HAZARD THIS FILE EXISTS FOR. config_json reaches the edge twice: once
// from Persist/Claim at registration, and again on every config-svc delta when
// anybody edits the tunnel. The delta never carries a secret. So the naive
// parse — "build the OAuth config from the blob" — means editing a tunnel's IP
// rules SILENTLY TURNS OFF ITS LOGIN, because the hot-swap replaces a policy
// that had a secret with one that could not be built. Nothing errors. The
// tunnel just stops asking who you are.
//
// The answer is that a policy referencing a named login is INCOMPLETE until a
// secret is supplied, and says so, rather than quietly becoming a policy with
// no OAuth in it.
//
// RUN: go test./apps/calabi-edge/internal/policy/ -run TestOAuthRef -v
package policy

import "testing"

const (
	refCfg = `{"security":{"oauth":{"from_policy":"acme-sso","provider":"github","client_id":"cid","allow_domains":["acme.com"]}}}`
	// The same tunnel also has an IP rule; editing THAT is what produces the
	// delta that used to wipe the login.
	refCfgWithIP = `{"security":{"ip":{"allow":["203.0.113.0/24"]},"oauth":{"from_policy":"acme-sso","provider":"github","client_id":"cid"}}}`
)

// The parse must report that a secret is owed, not silently drop the login.
func TestOAuthRefIsReportedAsNeedingASecret(t *testing.T) {
	p, err := Parse(refCfg)
	if err != nil || p == nil {
		t.Fatalf("parse: p=%v err=%v", p, err)
	}
	if got := p.OAuthPolicyRef(); got != "acme-sso" {
		t.Fatalf("OAuthPolicyRef = %q, want the policy name — the edge has no way to "+
			"know which secret to ask for", got)
	}
	if !p.NeedsOAuthSecret() {
		t.Fatal("the policy does not report a missing secret, so the caller will never fetch one " +
			"and the tunnel will serve with no login at all")
	}
	// And it must NOT claim to have a working login yet.
	if p.HasOAuth() {
		t.Fatal("HasOAuth is true before any secret arrived; the gate would try to run " +
			"with no credential")
	}
}

// Supplying the secret completes it.
func TestOAuthRefCompletesWithTheSecret(t *testing.T) {
	p, _ := Parse(refCfg)
	if err := p.ResolveOAuthSecret("gho_the_secret"); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !p.HasOAuth() {
		t.Fatal("the login is still not usable after the secret was supplied")
	}
	if p.NeedsOAuthSecret() {
		t.Fatal("still asking for a secret it already has")
	}
}

// THE regression this file is named for. A delta rebuilds the policy from a
// blob that has no secret; the caller must be able to carry the resolved one
// across, and the new policy must not pretend to be complete without it.
func TestOAuthRefSurvivesAHotSwapFromADelta(t *testing.T) {
	live, _ := Parse(refCfg)
	if err := live.ResolveOAuthSecret("gho_the_secret"); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	// Somebody edits the IP rules in the console. config-svc broadcasts the
	// whole config_json — still with no secret in it.
	next, err := Parse(refCfgWithIP)
	if err != nil || next == nil {
		t.Fatalf("parse delta: %v", err)
	}
	if !next.NeedsOAuthSecret() {
		t.Fatal("the delta's policy claims to be complete; whoever applies it will swap " +
			"away a working login without noticing")
	}
	// Carrying it across is one call, and it has to work on a policy the caller
	// did not build.
	if err := next.ResolveOAuthSecret(live.OAuthSecret()); err != nil {
		t.Fatalf("carry across: %v", err)
	}
	if !next.HasOAuth() || !next.HasIPRules() {
		t.Fatalf("after the swap: oauth=%v ip=%v — want both", next.HasOAuth(), next.HasIPRules())
	}
}

// A policy with no reference is untouched by any of this: an inline secret
// still works, which is what every tunnel configured before org policies
// existed still has.
func TestOAuthRefControlInlineSecretStillWorks(t *testing.T) {
	p, err := Parse(`{"security":{"oauth":{"provider":"github","client_id":"cid","client_secret":"inline"}}}`)
	if err != nil || p == nil {
		t.Fatalf("parse: %v", err)
	}
	if p.NeedsOAuthSecret() {
		t.Fatal("an inline-secret policy is asking for a secret it already has")
	}
	if p.OAuthPolicyRef() != "" {
		t.Fatalf("OAuthPolicyRef = %q, want empty", p.OAuthPolicyRef())
	}
	if !p.HasOAuth() {
		t.Fatal("an inline-secret policy did not produce a usable login")
	}
}

// Resolving with an empty secret is an error, not a silent no-op: the caller
// that got nothing back from the control plane must not conclude it is done.
func TestOAuthRefRefusesAnEmptySecret(t *testing.T) {
	p, _ := Parse(refCfg)
	if err := p.ResolveOAuthSecret("  "); err == nil {
		t.Fatal("an empty secret was accepted")
	}
	if p.HasOAuth() {
		t.Fatal("the login became usable after a failed resolve")
	}
}
