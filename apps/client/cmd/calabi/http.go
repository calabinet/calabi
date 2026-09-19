package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync"

	"github.com/calabi/calabi/apps/client/internal/creds"
	"github.com/calabi/calabi/apps/client/internal/platform/clientreg"
	"github.com/calabi/calabi/apps/client/internal/session"
	"github.com/calabi/calabi/apps/client/internal/status"
	proto "github.com/calabi/calabi/pkg/protocol"
)

// credentialKind classifies what resolveCredential picked, so callers can
// tailor messaging (an API-key failure is fixed differently than a login one).
type credentialKind int

const (
	credNone    credentialKind = iota
	credAPIKey                 // env CALABI_API_KEY/CALABI_TOKEN, or creds.APIKey
	credLogin                  // creds.AccessToken — an interactive user session
	credDefault                // the hard-coded demo token
)

// resolveCredential returns the bearer the client sends to calabi-edge and how it
// was sourced. Priority:
//
//  1. creds.AccessToken (a fresh interactive login) — ONLY when this is not a
//     real OS service. This is deliberately ABOVE the env key: a stale
//     CALABI_API_KEY left in the environment must not hijack the handshake
//     after the user signs in through the desktop app / SPA. Without it the
//     login appears to do nothing and the edge rejects with code 2002, even
//     though discovery (edgepicker, which already prefers the login) succeeds.
//  2. $CALABI_API_KEY env var (a tk_… API key; CI / scripts / installed service)
//  3. $CALABI_TOKEN env var (legacy alias of #2)
//  4. api_key from the creds file
//  5. access_token from the creds file (service context, where #1 was skipped)
//  6. defaultToken (the hard-coded value, kept for the demo path)
//
// A real service (inServiceManager) skips #1: it has no interactive user, its
// credential IS the env API key, and its creds file normally has no
// access_token anyway — so this only changes the interactive/desktop/foreground
// case, where "I just logged in" should win over a leftover env key.
func resolveCredential() (string, credentialKind) {
	c, _ := creds.Load()
	if !inServiceManager && c != nil && c.AccessToken != "" {
		return c.AccessToken, credLogin
	}
	if v := os.Getenv("CALABI_API_KEY"); v != "" {
		return v, credAPIKey
	}
	if v := os.Getenv("CALABI_TOKEN"); v != "" {
		return v, credAPIKey
	}
	if c != nil {
		if c.APIKey != "" {
			return c.APIKey, credAPIKey
		}
		if c.AccessToken != "" {
			return c.AccessToken, credLogin
		}
	}
	return defaultToken, credDefault
}

// resolveToken is the value-only form used everywhere a bearer is needed.
func resolveToken() string {
	t, _ := resolveCredential()
	return t
}

// resolveDeviceID loads the persisted device_id from creds; 0 = unknown.
//
// Core helper (only touches creds): http/tcp/udp/sni all stamp the AUTH frame
// with it, and on a standalone client it's simply 0 (no device registration
// ever ran). Lives here, with the core tunnel commands, rather than alongside
// the device-management command.
func resolveDeviceID() int64 {
	c, err := creds.Load()
	if err != nil || c == nil {
		return 0
	}
	return c.DeviceID
}

// ensureDeviceRegistered registers this machine as a client if it never has
// been, so the tunnel about to be created is attributable to a device.
//
// Why it is here and not only in the daemon: registration used to happen ONLY
// on the daemon path (clientreg.Ensure from runDaemon / `calabi clients
// register`), while the one-shot commands merely READ creds.DeviceID. On a
// machine where no daemon of this config has ever run, that id is 0 — so the
// tunnel is stored with client_id = 0, the console's client list has no row for
// the machine, and the state derivation skips every client-side signal it has
// (see web/console/src/lib/tunnelState.ts), which is how a tunnel whose local
// upstream is unreachable still read "正常".
//
// Deliberately narrow:
//   - Only when the id is MISSING. Re-registering on every `calabi http` would
//     put an HTTP round-trip in front of a command whose whole appeal is that it
//     starts immediately.
//   - Standalone mode has no control plane to register with.
//   - Best-effort: a failure is logged and the tunnel proceeds exactly as it did
//     before this existed. Being unlisted is worth a line in the log; it is not
//     worth refusing to open a tunnel over.
//
// The credential decides the shape, mirroring runDaemon: an API key registers
// the org-owned agent (EnsureAgent), a login registers the user's own device.
func ensureDeviceRegistered(logger *slog.Logger) {
	cfg, err := creds.Load()
	if err != nil {
		return
	}
	tok, kind := resolveCredential()
	if !shouldRegisterDevice(clientIsStandalone(), cfg, kind) {
		return
	}
	if kind == credAPIKey {
		err = clientreg.EnsureAgent(cfg, bffURL(), version, tok)
	} else {
		err = clientreg.Ensure(cfg, bffURL(), version)
	}
	if err != nil {
		logger.Warn("could not register this device; the tunnel will not be linked to a client",
			"err", err)
		return
	}
	logger.Info("registered this device", "client_id", cfg.DeviceID)
}

// shouldRegisterDevice is the decision half of ensureDeviceRegistered, split out
// because each "no" is a rule worth pinning rather than a detail: the whole
// point is that this costs a round-trip exactly once per machine, never on the
// paths where it would be wrong or useless.
func shouldRegisterDevice(standalone bool, cfg *creds.Config, kind credentialKind) bool {
	if standalone {
		return false // no control plane to register with
	}
	if cfg == nil {
		return false
	}
	if cfg.DeviceID != 0 {
		return false // already registered; re-asking would just add latency
	}
	// The demo token is not a credential: /v1/clients/register would 401 and
	// requireEdgeAddr is about to tell the user to sign in anyway.
	return kind != credDefault
}

// resolveFingerprint loads the persisted per-install fingerprint; "" = none.
//
// Unlike EnsureFingerprint this never CREATES one: a client that has no
// device registration should stay unlinked rather than mint an id that
// matches nothing on the Publish side.
//
// It takes a logger because the failure it can hit is INVISIBLE otherwise. A
// read error here — the container out of file descriptors, a config dir that
// isn't readable — returns exactly what "this machine has no device
// registration yet" returns, and the mesh node then enrols with no fingerprint
// and no explanation anywhere. That cost a production investigation: the daemon
// was registered and online, and nothing in any log said why the console
// couldn't link it to its client record.
func resolveFingerprint(logger *slog.Logger) string {
	c, err := creds.Load()
	if err != nil {
		if logger != nil {
			logger.Warn("could not read this install's device fingerprint; "+
				"mesh will enrol without it and the console can't link this device to its client record",
				"err", err)
		}
		return ""
	}
	if c == nil {
		return ""
	}
	return c.Fingerprint
}

// runHTTP implements `calabi http <port>`.
func runHTTP(args []string) int {
	fs := flag.NewFlagSet("http", flag.ContinueOnError)
	name := fs.String("name", "web", "tunnel name shown in dashboard")
	domain := fs.String("domain", "", "request a specific subdomain (empty = auto-assign)")
	host := fs.String("host", "127.0.0.1", "local bind host to forward to")
	sec := registerSecurityFlags(fs, true)
	if err := fs.Parse(reorderArgs(args, valueFlagsOf(fs))); err != nil {
		return 2
	}
	secJSON, secErr := sec.buildConfigJSON()
	if secErr != nil {
		fmt.Fprintln(os.Stderr, "calabi http:", secErr)
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "calabi http: missing <port>")
		fs.Usage()
		return 2
	}
	port, err := strconv.Atoi(fs.Arg(0))
	if err != nil || port <= 0 || port > 65535 {
		fmt.Fprintln(os.Stderr, "calabi http: invalid port:", fs.Arg(0))
		return 2
	}
	localAddr := fmt.Sprintf("%s:%d", *host, port)
	if err := validateLocalUpstream(localAddr); err != nil {
		fmt.Fprintln(os.Stderr, "calabi http:", err)
		return 1
	}

	logger := setupLogger()
	// Make this machine attributable before the tunnel exists: without a
	// device id the row is stored with client_id = 0 and the console can show
	// neither which machine it runs on nor whether that machine is up.
	ensureDeviceRegistered(logger)
	// calabi.net: CALABI_SERVER (or a baked default, if this build has one),
	// else the edge the control plane names — the same picker the daemon uses.
	// Self-hosted: the edge the coordinator this device joined names.
	edge, code := openOneShotEdge(logger, "http")
	if edge == nil {
		return code
	}
	defer edge.Close()
	edgeAddr := edge.addr

	cli := edge.newSession(logger, *name)

	state := status.New(version, edgeAddr)
	cli.AttachTracker(state)
	startStatusPage(logger, state)

	ctx, cancel := withSignalContext()
	defer cancel()

	if err := cli.Handshake(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "calabi: handshake:", err)
		return 1
	}
	edge.keepFresh(ctx, logger, cli)

	tun := session.Tunnel{
		Name:               *name,
		Type:               proto.ProxyKindHTTP,
		LocalAddr:          localAddr,
		Domain:             *domain,
		SecurityConfigJSON: secJSON,
	}
	assigned, err := cli.RegisterTunnel(ctx, tun)
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi: register tunnel:", err)
		return 1
	}
	// What the EDGE did with the policy we sent — not what we assumed it would.
	sec.NoteEdgePolicy(assigned.ClientPolicy)
	state.AddTunnel(status.TunnelInfo{
		ProxyID:    assigned.ProxyID,
		Name:       *name,
		Type:       "http",
		LocalAddr:  localAddr,
		PublicAddr: "http://" + assigned.Domain,
	})
	defer state.RemoveTunnel(assigned.ProxyID)

	// Resolver: proxy_id -> tunnel (gives LocalAddr to the dispatcher).
	var resolverMu sync.RWMutex
	proxies := map[string]session.Tunnel{assigned.ProxyID: tun}
	resolve := func(id string) (session.Tunnel, bool) {
		resolverMu.RLock()
		defer resolverMu.RUnlock()
		t, ok := proxies[id]
		return t, ok
	}

	fmt.Printf("\n  tunnel: http://%s  ->  %s\n\n", assigned.Domain, localAddr)
	fmt.Println("  Ctrl-C to quit.")

	if err := cli.Run(ctx, resolve); err != nil {
		logger.Info("session ended", "err", err)
	}
	return 0
}
