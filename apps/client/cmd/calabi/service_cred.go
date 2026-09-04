// service_cred_platform.go — resolve the credential to bake into the background
// service at `calabi daemon install` time.
//
// The service runs in a different OS account than your interactive shell
// (LocalSystem on Windows, root under systemd) and can't see the login in your
// user profile, so it needs its own long-lived API key. By design the client
// does NOT mint keys: you create one deliberately in the console (Account → API
// keys) and hand it to install. install only ever CONSUMES a key — it never
// calls a key-creation API. (A leaked data-plane key must not be able to mint
// more keys; key management is a logged-in-human action, gated server-side too.)

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/calabi/calabi/apps/client/internal/creds"
	"github.com/calabi/calabi/apps/client/internal/platform/bffclient"
)

// serviceInstallEnv returns the env vars to bake into the platform service at
// install. Returns (nil, nil) for the local-config service (`--config`), which
// authenticates from its YAML's token_env instead.
//
// The API key comes from `--api-key tk_…` (preferred) or the CALABI_API_KEY
// environment — never minted. Absent both, install fails with guidance. The key
// is returned as an env var (baked into the service env, never the command
// line, so it isn't visible in `sc qc`).
func serviceInstallEnv(installArgs []string) (map[string]string, error) {
	if extractFlagValue(installArgs, "config") != "" {
		return nil, nil // local supervisor daemon — creds come from tunnels.yaml
	}
	// Region / edge-affinity ride along in every mode so the service picks the
	// same edge as the user's interactive runs (e.g. a BYOI org's own edge).
	env := map[string]string{}
	if c, _ := creds.Load(); c != nil {
		if c.EdgeRegion != "" {
			env["CALABI_EDGE_REGION"] = c.EdgeRegion
		}
		if c.PreferPlatformEdge {
			env["CALABI_EDGE_AFFINITY"] = "platform"
		}
	}

	key := strings.TrimSpace(extractFlagValue(installArgs, "api-key"))
	if key == "" {
		key = strings.TrimSpace(os.Getenv("CALABI_API_KEY"))
	}
	if key == "" {
		// No key → an INTERACTIVE-mode service (not an error). It starts and
		// serves the local console, but stays dormant until someone signs in at
		// http://127.0.0.1:7400 — then it runs under that login. This is the
		// desktop / single-operator shape; an unattended client (servers / CI)
		// wants a pinned key instead. Guide the user but don't block the install.
		fmt.Fprintln(os.Stderr,
			"calabi daemon install: no API key given — installing an interactive client.\n"+
				"  It will wait until you sign in at http://127.0.0.1:7400 , then run as that account.\n"+
				"  For an unattended client (servers / CI) that connects on its own, reinstall with a key:\n"+
				"    calabi daemon install --api-key tk_…   (create one in the console → Account → API keys)")
		return env, nil
	}
	// Verify the key against the server before baking it into the service, so a
	// typo'd / revoked key is caught NOW instead of after the service starts and
	// silently fails its edge handshake (the user would otherwise only find out
	// by reading logs — exactly the trap one operator hit). Refuses only on an
	// explicit reject; an unreachable server warns and proceeds (don't block an
	// offline install — the key is re-checked when the service connects).
	// Indirected through a var so credential-resolution tests don't do network.
	if err := verifyInstallKeyFn(key); err != nil {
		return nil, err
	}
	env["CALABI_API_KEY"] = key
	return env, nil
}

// verifyInstallKeyFn is the seam serviceInstallEnv calls to validate the key.
// Defaults to the real network check; tests that only exercise credential
// resolution override it to avoid I/O.
var verifyInstallKeyFn = verifyInstallKey

// verifyInstallKey checks the API key against bff-console before install bakes
// it into the service env. Option A semantics:
//
//   - 200 → the key authenticates; proceed.
//   - 401 → the server rejected it (invalid or revoked) → return an error so
//     install refuses, with guidance to mint a fresh key.
//   - anything else (server unreachable, timeout, 5xx) → WARN to stderr and
//     proceed: we don't block an offline / control-plane-down install, and the
//     key is validated again for real when the service dials its edge.
//
// We validate the SAME credential the daemon's handshake will use (the key
// being installed, via /v1/account/me — an API-key-allowlisted endpoint that
// 401s a bad bearer at the auth gate), not the ambient login in creds. That
// matters because the edgepicker and the edge handshake resolve tokens in
// opposite precedence, so a stale login in creds could otherwise mask a bad
// service key.
func verifyInstallKey(key string) error {
	base := envOr("CALABI_BFF_CONSOLE", defaultBFFConsole)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	err := bffclient.New(base, key).Do(ctx, "GET", "/v1/account/me", nil, nil)
	switch {
	case err == nil:
		return nil
	case bffclient.IsStatus(err, 401):
		return errors.New(
			"the API key was rejected by the server (401 Unauthorized) — it's invalid or revoked.\n" +
				"Create a new key in the console (Account → API keys) and pass it:\n" +
				"  calabi daemon install --api-key tk_…")
	default:
		fmt.Fprintf(os.Stderr,
			"calabi daemon install: could not verify the API key (%v) — installing anyway; "+
				"it will be checked when the service connects.\n", err)
		return nil
	}
}
