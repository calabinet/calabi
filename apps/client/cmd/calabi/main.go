// calabi is the Calabi command-line client.
//
// Usage:
//
//	calabi http <port> [--name foo] [--domain x.example.com]
//	calabi version
//	calabi help
//
// Environment:
//
//	CALABI_SERVER   calabi-edge host:port (default: localhost:7443)
//	CALABI_API_KEY  API key for running tunnels (alias: CALABI_TOKEN)
//	CALABI_INSECURE if "1", skip TLS verification (dev)
//	CALABI_DEBUG    if "1", verbose logging
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/calabi/calabi/apps/client/internal/creds"
	"github.com/calabi/calabi/apps/client/internal/logging"
	"github.com/calabi/calabi/apps/client/internal/status"
)

// consoleURLFile is the basename the daemon writes its REAL bound console URL
// to (in its data dir), so a separate `calabi daemon start/status` invocation —
// which can't see the detached service's stdout — can read it back and print
// the address. For a service the data dir is the exe dir (creds.SetDataDir).
const consoleURLFile = "console.url"

// publishConsoleURL writes the bound console URL to <datadir>/console.url so the
// service-control commands can surface it. Best-effort; never fatal.
func publishConsoleURL(url string) {
	if url == "" {
		return
	}
	dir, err := creds.DataDir()
	if err != nil || dir == "" {
		return
	}
	p := filepath.Join(dir, consoleURLFile)
	tmp := p + ".tmp"
	if os.WriteFile(tmp, []byte(url+"\n"), 0o600) == nil {
		_ = os.Rename(tmp, p)
	}
}

// startStatusPage launches the local /status HTTP server in a background
// goroutine. Bind failure (port in use, etc.) is logged but never fatal --
// the tunnel always takes precedence over the diagnostics page.
//
// Address comes from CALABI_STATUS_ADDR or defaults to 127.0.0.1:7400.
// Set CALABI_STATUS_ADDR=disabled to suppress entirely.
func startStatusPage(logger *slog.Logger, state *status.State) {
	startStatusPageWithAPI(logger, state, nil)
}

// startStatusPageWithAPI is the daemon-mode variant that also attaches
// the writable /v1/* API surface. The api package builds its
// own registrar so status.go doesn't need to depend on it.
//
// AllowBrowser: the local dashboard is reachable from a plain browser, not
// just the Tauri desktop shell. The desktop-UA browserGuard was anti-footgun
// (steer users to the desktop app), NOT a security boundary — it's trivially
// bypassed with a curl -A header, mutating /v1/* stay local-token gated, and
// the server only binds 127.0.0.1. Platform users asked to open :7400 in a
// browser (screenshots / quick checks), so we relax it here too — matching
// the standalone `--local` console (startLocalConsole).
// startStatusPageWithAPI returns the ACTUAL console URL once bound (after any
// port fallback), or "" if the console is disabled / didn't bind in time. The
// daemon boot prints this so the user sees the real address rather than the
// requested-but-maybe-wrong default.
func startStatusPageWithAPI(logger *slog.Logger, state *status.State, attachAPI func(mux *http.ServeMux)) string {
	addr := envOr("CALABI_STATUS_ADDR", defaultStatusAddr)
	if strings.EqualFold(addr, "disabled") || addr == "off" {
		return ""
	}
	srv := status.NewServer(logger, state, addr)
	srv.AllowBrowser()
	if attachAPI != nil {
		srv.AttachAPI(attachAPI)
	}
	go func() {
		_ = srv.Run(context.Background())
	}()
	url := waitConsoleURL(srv)
	publishConsoleURL(url)
	return url
}

// waitConsoleURL blocks briefly for the server to report its real bound URL.
// The bind is near-instant; the timeout is just a safety cap so boot never
// hangs if the port is unbindable (then "" — the daemon falls back to printing
// the requested address).
func waitConsoleURL(srv *status.Server) string {
	select {
	case url := <-srv.Ready():
		return url
	case <-time.After(2 * time.Second):
		return ""
	}
}

// startLocalConsole launches the status server with a LOCAL /v1/* API (no
// bff-console proxy) and plain-browser access allowed — the self-hosted
// read-only console for `calabi daemon --local`. attachAPI is
// localweb.Server.Register. See internal/localweb + daemon_local.go.
func startLocalConsole(logger *slog.Logger, state *status.State, attachAPI func(mux *http.ServeMux)) string {
	addr := envOr("CALABI_STATUS_ADDR", defaultStatusAddr)
	if strings.EqualFold(addr, "disabled") || addr == "off" {
		return ""
	}
	srv := status.NewServer(logger, state, addr)
	srv.AllowBrowser()
	if attachAPI != nil {
		srv.AttachAPI(attachAPI)
	}
	go func() {
		_ = srv.Run(context.Background())
	}()
	url := waitConsoleURL(srv)
	publishConsoleURL(url)
	return url
}

// loggingHub is a thin accessor so the daemon command can defer Close() on the
// log hub without importing the logging package itself (keeps the cmd
// package's import graph minimal).
func loggingHub() interface{ Close() error } {
	if h := logging.GetHub(); h != nil {
		return h
	}
	return nil
}

const (
	defaultServer = "localhost:7443"
	defaultToken  = "dev-token-please-change"
	// defaultInsecure is false: the client verifies the edge :7443 control
	// cert against its embedded edge-CA root (+ optional CALABI_EDGE_CA_FILE)
	// by default. Set CALABI_INSECURE=1 to skip verification (dev with a
	// self-signed edge, or debugging). Dev normally keeps verification on and
	// points CALABI_EDGE_CA_FILE at deploy/dev/certs/ca.crt instead.
	defaultInsecure   = false
	defaultStatusAddr = "127.0.0.1:7400"
)

// defaultBFFConsole is the compile-time default control-plane endpoint (the
// daemon/CLI talk to bff-console for auth + edge discovery). It's a VAR, not a
// const, so a RELEASE build can bake the production URL via linker flags:
//
//	go build -ldflags "-X main.defaultBFFConsole=https://api.calabi.net"
//
// (scripts/package-release-client.sh does this). The dev default is the local
// port scripts/dev/run.ps1 binds bff-console to. A runtime $CALABI_BFF_CONSOLE
// still overrides this baked value.
var defaultBFFConsole = "http://127.0.0.1:8002"

// defaultConsoleWeb is the compile-time default WEB console origin — where a
// human signs up / manages their account in a browser. It is deliberately
// SEPARATE from defaultBFFConsole: the API endpoint and the web console are
// different hosts in production (api.calabi.net vs console.calabi.net), so the
// web URL cannot be derived from the API one. Same bakeable-var pattern:
//
//	go build -ldflags "-X main.defaultConsoleWeb=https://console.calabi.net"
//
// (scripts/package-release-client.sh + scripts/build-desktop.ps1 do this.) The
// dev default is the port scripts/dev/run.ps1 binds web/console to. A runtime
// $CALABI_CONSOLE_WEB overrides the baked value — a self-hosted deployment
// points this at its own console instead of the platform's.
//
// The daemon hands this to the SPA via GET /v1/service-mode so the login page
// can link to registration. Empty = the SPA hides the link rather than sending
// the user to a dead URL (which is what a hardcoded placeholder used to do).
var defaultConsoleWeb = "http://127.0.0.1:5173"

// version is the value printed by `calabi version`. It's a VAR, not a const, so
// a RELEASE build can bake the real version via linker flags:
//
//	go build -ldflags "-X main.version=1.2.1"
//
// (the package-release-client.sh / build-release-image.sh scripts do this from
// the repo-root VERSION file). As a const it was silently un-bakeable — `-X`
// only patches variables — so every release shipped reporting this dev default.
// The dev/un-baked default is intentionally "dev" to make non-release builds
// obvious;
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}
	cmd, rest := os.Args[1], os.Args[2:]

	switch cmd {
	case "http":
		os.Exit(runHTTP(rest))
	case "tcp":
		os.Exit(runTCP(rest))
	case "udp":
		os.Exit(runUDP(rest))
	case "sni":
		os.Exit(runSNI(rest))
	case "daemon":
		os.Exit(runDaemon(rest))
	case "register":
		// registration is only possible via the official console
		// (web/console). CLI used to dial identity-svc.Register directly,
		// but with the single-public-entry redesign that path is
		// gone — and operationally we want all signup flow (TOTP nudges,
		// CAPTCHA, marketing tags, ...) to live in one place.
		fmt.Fprintln(os.Stderr, "calabi register: removed — sign up on the website, then run `calabi login`")
		os.Exit(2)
	case "login":
		os.Exit(runLogin(rest))
	case "logout":
		os.Exit(runLogout(rest))
	case "certs":
		os.Exit(runCerts(rest))
	case "domains":
		os.Exit(runDomains(rest))
	case "clients":
		os.Exit(runClients(rest))
	case "org":
		// multi-Org switching.
		os.Exit(runOrg(rest))
	case "mode":
		// platform | standalone — the client's explicit operating mode.
		os.Exit(runMode(rest))
	case "ui":
		// Removed: `calabi ui` used to start its own (sessionless, empty)
		// status server and open a browser, which collided with the daemon
		// on :7400 and confused more than it helped. The dashboard is served
		// by the daemon — just open the URL.
		fmt.Fprintln(os.Stderr, "calabi ui: removed — open http://127.0.0.1:7400 in your browser. The dashboard is served by the daemon (`calabi login` starts one; or run `calabi daemon`).")
		os.Exit(2)
	case "version", "--version", "-v":
		fmt.Printf("calabi %s (%s edition)\n", version, edition)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "calabi: unknown command %q\n\n", cmd)
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `calabi -- Calabi client

Usage:
  calabi login    [--email EMAIL] [--password PW] [--totp CODE]
  calabi logout
  calabi certs    {upload|list|delete <id>} [--fullchain F] [--key K] [--name N]
  calabi domains  {create|verify|bind-cert|list|delete} <domain> [<cert-name>]
  calabi clients  {list|register}
  calabi org      {list|current|switch <id|name>}
  calabi mode     [platform|standalone]   (show or set the client mode)
  calabi daemon [--name NAME]
     (stay online without opening any tunnel; the web console shows
      this client as online as long as the process is running)
  calabi daemon --local --config tunnels.yaml
     (self-hosted: run every tunnel from a local YAML config against your
      own edge, with per-tunnel access control; auto-reconnects. No account
      or control plane needed. See docs/examples/tunnels.yaml)
  calabi daemon install --config tunnels.yaml
     (install the local daemon as a boot-start OS service; then manage with
      calabi daemon {start|stop|status|restart|uninstall})
  calabi http <local-port> [--name NAME] [--domain DOMAIN]
  calabi tcp  <local-port> [--name NAME] [--remote-port N]
  calabi udp  <local-port> [--name NAME] [--remote-port N]
  calabi version
  calabi help

Access control (self-hosted / standalone edge only):
  http/tcp/udp accept  --ip-allow CIDR  --ip-deny CIDR  --rate N
  http additionally accepts --basic-auth user:pass  --set-header "K: V"
  --del-header K  --oauth-provider google|github  --oauth-client-id ID
  --oauth-client-secret SECRET  --oauth-allow-email/-domain  and
  --security-file FILE (a full {"security":{…}} blob). These take effect
  ONLY against an edge run with mode: standalone (CALABI_EDGE_MODE=standalone)
  and no control plane wired; on the managed platform / BYOI, access control
  is configured in the web console. Pass --standalone to silence the warning.

Note:
  User registration is only available via the official web console;
  use "calabi login" once your account exists.

Environment:
  CALABI_BFF_CONSOLE   bff-console base URL — single public endpoint
                       for login / keys / certs / domains / org
                       (overrides the build-time default endpoint)
  CALABI_SERVER        calabi-edge host:port (optional, fallback when
                       /v1/edges returns nothing) (default: localhost:7443)
  CALABI_API_KEY       API key (tk_…) for running tunnels; overrides creds file
  CALABI_TOKEN         legacy alias of CALABI_API_KEY (back-compat)
  CALABI_INSECURE      "1" to skip TLS verification (dev)
  CALABI_DEBUG         "1" for verbose logging
  CALABI_CONFIG        path to credentials file (default: per-OS config dir)

Examples:
  calabi login    --email me@example.com --password '...'
  calabi http 8080
  calabi daemon install --api-key tk_…   (create the key in the console)`)
}

// setupLogger initializes the foreground-CLI logger: stderr only, no file
// sink. Foreground runs are short-lived (`calabi http <port>`, `calabi
// login`, ...) — writing to disk would clutter ~/.config without giving
// the user anything they couldn't see in their terminal.
//
// The daemon command (runDaemon) uses setupDaemonLogger instead so logs
// reach the rotated file under <config-dir>/logs/ as well, since service
// managers detach stderr.
func setupLogger() *slog.Logger {
	return logging.Setup(logging.Options{DisableFile: true})
}

// setupDaemonLogger is the logger flavour for `calabi daemon`: stderr +
// rotated file + in-process ring/SSE hub. The hub lets /logs and
// /logs/stream serve UI-side log viewers without re-opening the file.
//
// As an OS service the default per-user log path is useless: a Windows
// LocalSystem service has no LOCALAPPDATA, so the path falls back to an
// ACL-protected systemprofile location you can't even find (you can't see why
// the daemon won't connect). When running under the service manager we instead
// pin the log next to the executable — predictable and readable.
func setupDaemonLogger() *slog.Logger {
	opts := logging.Options{}
	if inServiceManager {
		if p := serviceLogPath(); p != "" {
			opts.FilePath = p
		}
	}
	return logging.Setup(opts)
}

// serviceLogPath returns "<dir of the running binary>/calabi.log" — where a
// service writes its log so it's always next to the exe. "" if the executable
// path can't be resolved (caller falls back to the default).
func serviceLogPath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(exe), "calabi.log")
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v == "1" || strings.EqualFold(v, "true")
}

func withSignalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	// Also cancel when the OS service manager asks us to stop (serviceStop,
	// closed by serviceProgram.Stop). serviceStop only ever closes under a
	// service-manager launch, so foreground commands are unaffected. The
	// goroutine exits on ctx.Done(), so short-lived commands don't leak it.
	go func() {
		select {
		case <-serviceStop:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}
