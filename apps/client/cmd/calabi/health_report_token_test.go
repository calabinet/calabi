// health_report_token_test.go — the upstream-health reporter must find the
// credential an AGENT actually runs with.
//
// THE BUG. An installed service's API key lives in $CALABI_API_KEY — nothing in
// the client ever writes api_key into the creds FILE (the only three
// assignments to creds.Config.APIKey set it to ""). resolveCredential(), which
// the rest of the daemon uses, knows that: env is source #2. The reporter had
// its own private resolver that read the file and nothing else, so on every
// agent-mode daemon it got "" and tick() returned at
//
//	token := resolveReportToken()
//	if token == "" { return }
//
// before looking at a single probe result. Not one upstream-health report, ever,
// for any tunnel — the healthy ones included. The console therefore showed 在线
// for a tunnel whose local upstream had been refusing connections for 208
// consecutive probes, while the same org's OTHER machine — an interactive login,
// whose creds file does carry access_token — reported fine. That difference is
// what made it look like an edge-type problem.
//
// Second implementation of a rule that already had one. The comment on the old
// resolver even said it "mirrors clientreg.tokenFor" — it mirrored the wrong
// function; clientreg is only ever called on the post-login path, where the file
// always has a token.
//
// RUN: go test./apps/client/cmd/calabi/ -run TestUpstreamHealthToken -v
package main

import (
	"os"
	"path/filepath"
	"testing"
)

// emptyCreds points creds.Load at a path with no file: an agent's state, where
// the credential exists only in the environment.
func emptyCreds(t *testing.T) {
	t.Helper()
	t.Setenv("CALABI_CONFIG", filepath.Join(t.TempDir(), "creds.json"))
	os.Unsetenv("CALABI_API_KEY")
	os.Unsetenv("CALABI_TOKEN")
}

func TestUpstreamHealthTokenFindsTheAgentsEnvKey(t *testing.T) {
	emptyCreds(t)
	t.Setenv("CALABI_API_KEY", "tk_agent_key")

	if got := resolveReportToken(); got != "tk_agent_key" {
		t.Fatalf("resolveReportToken() = %q, want the env API key — an agent's "+
			"credential is never in the creds file, so a file-only lookup reports "+
			"nothing for the life of the process", got)
	}
}

// The legacy alias the rest of the daemon honours.
func TestUpstreamHealthTokenFindsTheLegacyEnvAlias(t *testing.T) {
	emptyCreds(t)
	t.Setenv("CALABI_TOKEN", "tk_legacy")

	if got := resolveReportToken(); got != "tk_legacy" {
		t.Fatalf("resolveReportToken() = %q, want the CALABI_TOKEN alias", got)
	}
}

// With nothing anywhere, report nothing. resolveCredential's last source is the
// demo constant; posting that to bff-console would 401 every 30 seconds
// forever and tell the user nothing.
func TestUpstreamHealthTokenRefusesTheM1DemoDefault(t *testing.T) {
	emptyCreds(t)

	if got := resolveReportToken(); got != "" {
		t.Fatalf("resolveReportToken() = %q, want \"\" — there is no credential "+
			"here, and the hard-coded demo token is not one", got)
	}
}

// The reporter and the session must not disagree about who this daemon is: a
// report attributed to a different principal than the one that claimed the
// tunnel is exactly the 403 this endpoint's authorization would produce.
func TestUpstreamHealthTokenMatchesTheSessionCredential(t *testing.T) {
	emptyCreds(t)
	t.Setenv("CALABI_API_KEY", "tk_agent_key")

	if got, want := resolveReportToken(), resolveToken(); got != want {
		t.Fatalf("reporter uses %q but the session authenticates with %q", got, want)
	}
}
