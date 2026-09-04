package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync"

	"github.com/calabi/calabi/apps/client/internal/creds"
	"github.com/calabi/calabi/apps/client/internal/session"
	"github.com/calabi/calabi/apps/client/internal/status"
	"github.com/calabi/calabi/apps/client/internal/transport"
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
				"mesh will enrol without it and the console can't link this node to its client record",
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
	sec, secNames := registerSecurityFlags(fs, true)
	if err := fs.Parse(reorderArgs(args, append([]string{"name", "domain", "host"}, secNames...))); err != nil {
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
	logger.Info("connecting",
		"server", envOr("CALABI_SERVER", defaultServer),
		"local", localAddr)

	mux, err := transport.Dial(transport.DialOptions{
		Addr:       envOr("CALABI_SERVER", defaultServer),
		Insecure:   envBool("CALABI_INSECURE", defaultInsecure),
		CACertFile: envOr("CALABI_EDGE_CA_FILE", ""),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi: dial:", err)
		return 1
	}

	cli := session.New(logger, mux, resolveToken(), *name)
	cli.SetDeviceID(resolveDeviceID())

	state := status.New(version, envOr("CALABI_SERVER", defaultServer))
	cli.AttachTracker(state)
	startStatusPage(logger, state)

	ctx, cancel := withSignalContext()
	defer cancel()

	if err := cli.Handshake(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "calabi: handshake:", err)
		return 1
	}

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
