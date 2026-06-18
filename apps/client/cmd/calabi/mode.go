package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/calabi/calabi/apps/client/internal/creds"
)

// Client operating mode — the explicit counterpart to the edge's top-level
// `mode`. It declares whether this client targets the managed platform or a
// self-hosted (standalone) edge.
const (
	clientModePlatform   = "platform"
	clientModeStandalone = "standalone"
)

// resolveClientMode returns the effective client mode, with precedence:
//
//	CALABI_MODE env  >  persisted creds.Config.Mode  >  defaultClientMode
//
// defaultClientMode is a build-tagged constant: "standalone" in this build
// (which has no control-plane code), "platform" in the platform build. An
// explicit CALABI_MODE / persisted value other than "standalone" resolves to
// "platform"; absent both, the default holds — so a standalone binary needs no
// --local / --standalone, while the platform binary stays managed-by-default.
func resolveClientMode() string {
	if v := strings.TrimSpace(os.Getenv("CALABI_MODE")); v != "" {
		if strings.EqualFold(v, clientModeStandalone) {
			return clientModeStandalone
		}
		return clientModePlatform
	}
	if c, err := creds.Load(); err == nil && c != nil {
		if m := strings.TrimSpace(c.Mode); m != "" {
			if strings.EqualFold(m, clientModeStandalone) {
				return clientModeStandalone
			}
			return clientModePlatform
		}
	}
	return defaultClientMode
}

// clientIsStandalone is the boolean shorthand used by the tunnel commands.
func clientIsStandalone() bool { return resolveClientMode() == clientModeStandalone }

// runMode implements `calabi mode [standalone|platform]`.
//
//	calabi mode               -> print the effective mode + explanation
//	calabi mode standalone    -> persist standalone to the config file
//	calabi mode platform      -> persist platform to the config file
func runMode(args []string) int {
	if len(args) == 0 {
		fmt.Printf("client mode: %s\n", resolveClientMode())
		if v := strings.TrimSpace(os.Getenv("CALABI_MODE")); v != "" {
			fmt.Printf("  (overridden this shell by CALABI_MODE=%s)\n", v)
		}
		fmt.Println("  platform   — managed platform: login / daemon / edge discovery via bff-console")
		fmt.Println("  standalone — self-hosted: tunnels target your own edge (CALABI_SERVER + CALABI_TOKEN),")
		fmt.Println("               no bff-console; --ip-allow/--basic-auth/… are applied by your standalone edge")
		return 0
	}
	want := strings.ToLower(strings.TrimSpace(args[0]))
	if want != clientModeStandalone && want != clientModePlatform {
		fmt.Fprintf(os.Stderr, "calabi mode: want %q or %q, got %q\n",
			clientModeStandalone, clientModePlatform, args[0])
		return 2
	}
	c, err := creds.Load()
	if err != nil || c == nil {
		c = &creds.Config{}
	}
	c.Mode = want
	if err := creds.Save(c); err != nil {
		fmt.Fprintln(os.Stderr, "calabi mode: save:", err)
		return 1
	}
	fmt.Printf("client mode set to %q\n", want)
	if v := strings.TrimSpace(os.Getenv("CALABI_MODE")); v != "" && !strings.EqualFold(v, want) {
		fmt.Fprintf(os.Stderr,
			"note: CALABI_MODE=%s is set and overrides the saved value for this shell\n", v)
	}
	return 0
}
