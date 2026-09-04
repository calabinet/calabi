package main

import (
	"strings"
	"testing"
)

// prodEnv sets every var checkProductionPosture reads, so a case states the
// WHOLE environment rather than inheriting leftovers from the shell or a
// previous case. Both namespaces are cleared and only the CURRENT one is set;
// the legacy names get their own test below.
func prodEnv(t *testing.T, calabiEnv, identity, allowNoAuth, quotaAddr, nodeQuota string) {
	t.Helper()
	t.Setenv("CALABI_ENV", calabiEnv)
	for _, p := range []string{envPrefix, legacyEnvPrefix} {
		t.Setenv(p+"_IDENTITY_ADDR", "")
		t.Setenv(p+"_AUTHKEYS_FILE", "")
		t.Setenv(p+"_MESH_ADMIN_ALLOW_NOAUTH", "")
		t.Setenv(p+"_QUOTA_ADDR", "")
		t.Setenv(p+"_NODE_QUOTA", "")
	}
	t.Setenv("QUOTA_SVC_ADDR", "")
	t.Setenv(envPrefix+"_IDENTITY_ADDR", identity)
	t.Setenv(envPrefix+"_MESH_ADMIN_ALLOW_NOAUTH", allowNoAuth)
	t.Setenv(envPrefix+"_QUOTA_ADDR", quotaAddr)
	t.Setenv(envPrefix+"_NODE_QUOTA", nodeQuota)
}

// TestProductionPostureAllowsAHealthyDeployment pins that the guard is silent
// for the real production wiring — a guard that fires on the actual deployment
// would just get disabled.
func TestProductionPostureAllowsAHealthyDeployment(t *testing.T) {
	// Exactly what deploy/compose/docker-compose.yml sets for calabi-coord.
	prodEnv(t, "production", "identity-svc:7001", "", "quota-svc:7004", "")
	if err := checkProductionPosture(); err != nil {
		t.Fatalf("healthy production posture rejected: %v", err)
	}
}

// TestProductionPostureIgnoredOutsideProduction pins that a dev stack keeps
// every fallback: the guard must not make local development harder.
func TestProductionPostureIgnoredOutsideProduction(t *testing.T) {
	for _, env := range []string{"", "dev", "staging", "Production-ish"} {
		t.Run("CALABI_ENV="+env, func(t *testing.T) {
			prodEnv(t, env, "", "1", "", "")
			if err := checkProductionPosture(); err != nil {
				t.Fatalf("guard fired outside production (CALABI_ENV=%q): %v", env, err)
			}
		})
	}
}

// TestProductionPostureRejectsFailOpen walks each degradation the plan lists.
func TestProductionPostureRejectsFailOpen(t *testing.T) {
	cases := []struct {
		name        string
		identity    string
		allowNoAuth string
		quotaAddr   string
		nodeQuota   string
		wantMention string
	}{
		{
			name:        "no identity source means dev static auth",
			identity:    "",
			quotaAddr:   "quota-svc:7004",
			wantMention: "CALABI_COORD_IDENTITY_ADDR",
		},
		{
			name:        "unauthenticated mesh-admin escape hatch",
			identity:    "identity-svc:7001",
			allowNoAuth: "1",
			quotaAddr:   "quota-svc:7004",
			wantMention: "CALABI_COORD_MESH_ADMIN_ALLOW_NOAUTH",
		},
		{
			name:        "no quota source means unlimited seats",
			identity:    "identity-svc:7001",
			wantMention: "UNLIMITED",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			prodEnv(t, "production", c.identity, c.allowNoAuth, c.quotaAddr, c.nodeQuota)
			err := checkProductionPosture()
			if err == nil {
				t.Fatal("production posture accepted a fail-open fallback")
			}
			if !strings.Contains(err.Error(), c.wantMention) {
				t.Errorf("error does not name the offending setting %q: %v", c.wantMention, err)
			}
		})
	}
}

// TestProductionPostureReportsEveryProblem: an operator fixing a boot failure
// should see the full list, not discover them one restart at a time.
func TestProductionPostureReportsEveryProblem(t *testing.T) {
	prodEnv(t, "production", "", "1", "", "")
	err := checkProductionPosture()
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{
		"CALABI_COORD_IDENTITY_ADDR",
		"CALABI_COORD_MESH_ADMIN_ALLOW_NOAUTH",
		"UNLIMITED",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("combined error is missing %q: %v", want, err)
		}
	}
	if !strings.Contains(err.Error(), "3 fail-open") {
		t.Errorf("error should count all three problems: %v", err)
	}
}

// TestStaticNodeQuotaSatisfiesTheGuard documents the intended escape hatch:
// stating a static cap on purpose is a legal production posture.
func TestStaticNodeQuotaSatisfiesTheGuard(t *testing.T) {
	prodEnv(t, "production", "identity-svc:7001", "", "", "50")
	if err := checkProductionPosture(); err != nil {
		t.Fatalf("an explicit CALABI_COORD_NODE_QUOTA should be accepted: %v", err)
	}
}

// TestSelfHostedAuthKeysFileIsAProductionPosture: a self-hoster runs coord with
// their own key -> meshnet map and no identity source at all. That is the shape
// authstub.go documents as the self-hosted coordinator's real configuration, so
// production must accept it. An earlier version of the guard demanded
// identity-svc outright and would have called this deployment broken.
func TestSelfHostedAuthKeysFileIsAProductionPosture(t *testing.T) {
	prodEnv(t, "production", "", "", "", "50")
	t.Setenv(envPrefix+"_AUTHKEYS_FILE", "/etc/calabi/authkeys.json")
	if err := checkProductionPosture(); err != nil {
		t.Fatalf("a self-hosted coordinator with its own auth-keys file was rejected: %v", err)
	}
}

// TestNoAuthSourceAtAllIsRefused: neither posture configured means the built-in
// key admits anyone into meshnet 1.
func TestNoAuthSourceAtAllIsRefused(t *testing.T) {
	prodEnv(t, "production", "", "", "", "50")
	err := checkProductionPosture()
	if err == nil {
		t.Fatal("production accepted the built-in dev key as its only authentication")
	}
	if !strings.Contains(err.Error(), "CALABI_COORD_AUTHKEYS_FILE") {
		t.Errorf("the error should offer the self-hosted option too, got: %v", err)
	}
}

// TestLegacyEnvNamesStillConfigureProduction is the compatibility contract for
// the CALABI_COORD_* rename (full-oss-plan 12.5).
//
// A deployment that predates the rename sets only COORD_SVC_* (and the platform
// name QUOTA_SVC_ADDR). If those stopped counting, this guard would refuse to
// start a stack that is configured correctly by the rules it was deployed under
// — a rename would become an outage. So: same environment, old spellings,
// still healthy.
func TestLegacyEnvNamesStillConfigureProduction(t *testing.T) {
	prodEnv(t, "production", "", "", "", "")
	t.Setenv(legacyEnvPrefix+"_IDENTITY_ADDR", "identity-svc:7001")
	t.Setenv("QUOTA_SVC_ADDR", "quota-svc:7004")
	if err := checkProductionPosture(); err != nil {
		t.Fatalf("a pre-rename deployment was rejected: %v", err)
	}
}

// TestCurrentEnvNameWinsOverLegacy: with both set, the new name decides. An
// operator mid-migration has the old value still in place; if the stale one won,
// their new setting would silently do nothing.
func TestCurrentEnvNameWinsOverLegacy(t *testing.T) {
	t.Setenv(envPrefix+"_IDENTITY_ADDR", "new:7001")
	t.Setenv(legacyEnvPrefix+"_IDENTITY_ADDR", "old:7001")
	if got := env("IDENTITY_ADDR"); got != "new:7001" {
		t.Fatalf("env() = %q, want the CALABI_COORD_ value to win", got)
	}
}

// TestLegacyEnvUseIsRecorded: compatibility that says nothing is how a
// deprecated name survives for years. Reading one must leave a trace for
// reportLegacyEnv to log at startup.
func TestLegacyEnvUseIsRecorded(t *testing.T) {
	legacyMu.Lock()
	legacySeen = map[string]string{}
	legacyMu.Unlock()

	t.Setenv(envPrefix+"_POLICY_FILE", "")
	t.Setenv(legacyEnvPrefix+"_POLICY_FILE", "/etc/acl.json")
	if got := env("POLICY_FILE"); got != "/etc/acl.json" {
		t.Fatalf("env() = %q, want the legacy value", got)
	}

	legacyMu.Lock()
	got, ok := legacySeen[legacyEnvPrefix+"_POLICY_FILE"]
	legacyMu.Unlock()
	if !ok {
		t.Fatal("reading a deprecated name left no trace, so startup would never warn about it")
	}
	if want := envPrefix + "_POLICY_FILE"; got != want {
		t.Errorf("recorded replacement %q, want %q", got, want)
	}
}
