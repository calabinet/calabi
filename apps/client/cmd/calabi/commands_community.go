package main

// commands_community.go is the community-edition command surface: it compiles
// ONLY under `-tags community`, replacing the platform command files
// (account / certs / clients / domains / org / daemon) — which talk to
// bff-console — with stubs. A community client is a pure data-plane tunneler:
// `calabi http|tcp|udp` (with --standalone security flags) against your own
// `mode: standalone` edge, plus `mode` / `ui` / `version` / `help`. Account,
// org, cert, domain and device management live in the hosted control plane and
// are not part of the open-source client.

import (
	"fmt"
	"os"
)

// edition labels this build for `calabi version`.
const edition = "community"

// defaultClientMode makes this build standalone out of the box: it has no
// control-plane code, so "platform" is never a usable mode here. This is what
// lets `calabi http …` and `calabi daemon --config …` work WITHOUT --standalone
// / --local — those flags only ever override this default. (CALABI_MODE / a
// persisted `calabi mode` still override.) Read by resolveClientMode in mode.go.
const defaultClientMode = clientModeStandalone

// notInCommunity prints a consistent refusal for a platform-only command and
// returns exit code 2 (usage error), matching the CLI's other unsupported-path
// messages (e.g. `calabi register`).
func notInCommunity(cmd string) int {
	fmt.Fprintf(os.Stderr,
		"calabi %s: this command is platform-only. The Community Edition (standalone) is a "+
			"pure data-plane tunneler — it supports http/tcp/udp (with "+
			"--ip-allow/--basic-auth/--rate/--oauth-* access control) plus mode/ui/version. "+
			"Account, org, certificate, domain and device management live in the hosted "+
			"control plane.\n", cmd)
	return 2
}

func runLogin(args []string) int   { return notInCommunity("login") }
func runLogout(args []string) int  { return notInCommunity("logout") }
func runCerts(args []string) int   { return notInCommunity("certs") }
func runDomains(args []string) int { return notInCommunity("domains") }
func runClients(args []string) int { return notInCommunity("clients") }
func runOrg(args []string) int     { return notInCommunity("org") }

// runDaemon in the community build serves the LOCAL supervisor daemon
// (`calabi daemon --local --config tunnels.yaml`, daemon_local.go — compiled
// into both editions). The platform-sync daemon (presence + bff-console
// CONFIG_PUSH claim) is platform-only, so a bare `calabi daemon` here points
// the user at --local.
func runDaemon(args []string) int {
	// OS-service management for the LOCAL daemon. service.go is core, so
	// install/start/stop/… work in the community build too — `install` must
	// carry --config so the installed service launches the local runner
	// (`calabi daemon --local --config <abs path>`) rather than the (absent)
	// platform daemon.
	if len(args) > 0 {
		switch args[0] {
		case "install", "uninstall", "start", "stop", "status", "restart":
			if args[0] == "install" && extractFlagValue(args[1:], "config") == "" {
				fmt.Fprintln(os.Stderr,
					"calabi daemon install: the Community Edition only has the local daemon. "+
						"Pass --config tunnels.yaml to install it as a boot-start service "+
						"(runs `calabi daemon --local --config …`).")
				return 2
			}
			return runDaemonService(args)
		}
	}
	// When the Windows SCM launched us, drive the daemon through the service
	// control dispatcher so SCM gets its connection within the start timeout
	// (otherwise: error 1053). No-op elsewhere; the real boot runs inside
	// serviceProgram.Start. The installed community service is always --local.
	if handled, code := maybeRunUnderServiceManager(); handled {
		return code
	}
	if daemonIsLocal(args) {
		return runLocalDaemon(args)
	}
	fmt.Fprintln(os.Stderr,
		"calabi daemon: the platform-sync daemon is platform-only. For self-hosting use "+
			"`calabi daemon --local --config tunnels.yaml` (or `calabi mode standalone` then `calabi daemon`).")
	return 2
}
