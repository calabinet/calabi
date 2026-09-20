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
//	CALABI_SERVER   calabi-edge host:port (default: discovered via your account)
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

	"github.com/calabinet/calabi/apps/client/internal/creds"
	"github.com/calabinet/calabi/apps/client/internal/logging"
	"github.com/calabinet/calabi/apps/client/internal/platform/edgepicker"
	"github.com/calabinet/calabi/apps/client/internal/status"
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

// startStatusPage launches a one-shot command's local /status page in a
// background goroutine. Bind failure (port in use, etc.) is logged but never
// fatal -- the tunnel always takes precedence over the diagnostics page.
//
// Address comes from CALABI_STATUS_ADDR or defaults to 127.0.0.1:7400 (the
// next free port when a daemon holds it). Set CALABI_STATUS_ADDR=disabled to
// suppress entirely.
//
// It does NOT write console.url: that file says where this client's DAEMON is,
// and `calabi join`, `calabi mesh up|down|status` and `calabi daemon status`
// go there. A `calabi http` started beside the daemon used to take it over, and
// those commands then spoke to the one-shot's page (404) instead.
//
// AllowBrowser: the local dashboard is reachable from a plain browser, not
// just the Tauri desktop shell. The desktop-UA browserGuard was anti-footgun
// (steer users to the desktop app), NOT a security boundary — it's trivially
// bypassed with a curl -A header, and the server only binds 127.0.0.1.
func startStatusPage(logger *slog.Logger, state *status.State) {
	addr := envOr("CALABI_STATUS_ADDR", defaultStatusAddr)
	if strings.EqualFold(addr, "disabled") || addr == "off" {
		return
	}
	srv := status.NewServer(logger, state, addr)
	srv.AllowBrowser()
	configureConsoleUnlock(logger, srv, addr)
	go func() {
		_ = srv.Run(context.Background())
	}()
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

// publishConsoleURLLate covers the case where the bind took longer than
// waitConsoleURL's two seconds.
//
// Ready() is buffered(1) and written exactly once, so a slow bind still lands
// its value there — and before this, NOBODY EVER READ IT. The daemon then ran
// for its whole life with the PREVIOUS run's console.url on disk: a file naming
// a port this daemon does not serve. Anything that trusted it (a `calabi login`
// handing the session over, `calabi daemon status`, the mesh's console probe)
// was sent somewhere dead, and the file gave no hint it was stale.
//
// Two seconds is not generous when the requested port is taken: listenWithFallback
// scans up to twenty ports, and each attempt is a syscall against a loopback
// stack that a busy machine can make wait.
//
// No-op when the first wait already got it. The timeout bounds the goroutine for
// the one case Ready never fires at all — the bind failed outright, which the
// server logs as "status page unavailable".
func publishConsoleURLLate(srv *status.Server, already string) {
	if already != "" {
		return
	}
	go func() {
		select {
		case url := <-srv.Ready():
			publishConsoleURL(url)
		case <-time.After(60 * time.Second):
		}
	}()
}

// startDaemonConsole is the daemons' console: the status server with the
// daemon's /v1/* API (statusapi for the platform daemon, localweb for the local
// one) and plain-browser access allowed. It stops when ctx ends; done closes once
// the listener is released, which is what lets the other daemon take the same
// port when the console switches between calabi.net and a self-hosted server
// (daemon_restart.go) — bound while the old one still held it, it would fall
// back to the next port and the open page would lose its daemon.
func startDaemonConsole(ctx context.Context, logger *slog.Logger, state *status.State, attachAPI func(mux *http.ServeMux)) (string, <-chan struct{}) {
	done := make(chan struct{})
	addr := envOr("CALABI_STATUS_ADDR", defaultStatusAddr)
	if strings.EqualFold(addr, "disabled") || addr == "off" {
		close(done)
		return "", done
	}
	srv := status.NewServer(logger, state, addr)
	srv.AllowBrowser()
	configureConsoleUnlock(logger, srv, addr)
	if attachAPI != nil {
		srv.AttachAPI(attachAPI)
	}
	go func() {
		defer close(done)
		_ = srv.Run(ctx)
	}()
	url := waitConsoleURL(srv)
	publishConsoleURL(url)
	publishConsoleURLLate(srv, url)
	return url, done
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
	defaultToken = "dev-token-please-change"
	// defaultInsecure is false: the client verifies the edge :7443 control
	// cert against its embedded edge-CA root (+ optional CALABI_EDGE_CA_FILE)
	// by default. Set CALABI_INSECURE=1 to skip verification (dev with a
	// self-signed edge, or debugging). Dev normally keeps verification on and
	// points CALABI_EDGE_CA_FILE at deploy/dev/certs/ca.crt instead.
	defaultInsecure   = false
	defaultStatusAddr = "127.0.0.1:7400"
)

// defaultServer is the edge address used when CALABI_SERVER is unset. The value
// here is the DEV stack's; a release stamps it (scripts/package-release-client.sh,
// -X main.defaultServer) — normally to EMPTY, because a platform build discovers
// its edge through bff-console and there is no single production edge to name.
//
// Empty is not a hole: the daemon's picker refuses a loopback/blank fallback once
// a control plane is configured (edgepicker.Result.NoUsableEdge), and the one-shot
// tunnel commands discover an edge through the same picker (requireEdgeAddr),
// falling back to saying what to set. Shipping localhost made an unrelated DNS
// failure look like a dev build had been released by mistake.
//
// A VAR, and that is the whole point: it lived in the const block above for one
// build, where -X is SILENTLY IGNORED — the linker does not warn, so the release
// looked correct and shipped the dev address anyway. TestLdflagsTargetsAreVars
// now fails the build instead.
var defaultServer = "localhost:7443"

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
	case "join":
		// A self-hosted server's invite: the counterpart of login.
		os.Exit(runJoin(rest))
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
	case "mesh":
		// The WireGuard mesh subsystem — `calabi mesh up|status|down`.
		os.Exit(runMesh(rest))
	case "ui":
		// Removed: `calabi ui` used to start its own (sessionless, empty)
		// status server and open a browser, which collided with the daemon
		// on :7400 and confused more than it helped. The dashboard is served
		// by the daemon — just open the URL.
		fmt.Fprintln(os.Stderr, "calabi ui: removed — open http://127.0.0.1:7400 in your browser. The dashboard is served by the daemon (`calabi login` starts one; or run `calabi daemon`).")
		os.Exit(2)
	case "update":
		// The notification surface for machines with no screen: a Linux server or
		// an unattended agent never opens the :7400 console, and those are the
		// installs most likely to sit versions behind.
		os.Exit(runUpdate(rest))
	case "version", "--version", "-v":
		fmt.Printf("calabi %s\n", version)
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
  calabi join     [--name NAME] <invite>
     (self-hosted: join your server with the calabi://join link
      "calabi-coord invite" prints; then tunnels and the mesh work)
  calabi certs    {upload|list|delete <id>} [--fullchain F] [--key K] [--name N]
  calabi domains  {create|verify|bind-cert|list|delete} <domain> [<cert-name>]
  calabi clients  {list|register}
  calabi org      {list|current|switch <id|name>}
  calabi mode     [platform|standalone]   (show or set the client mode)
  calabi daemon [--name NAME]
     (stay online without opening any tunnel; the web console shows
      this client as online as long as the process is running)
  calabi daemon --local --config tunnels.yaml
     (self-hosted: run every tunnel from a local YAML config, with
      per-tunnel access control, on the edge of the server this device
      joined; auto-reconnects. See docs/examples/tunnels.yaml)
  calabi daemon install --config tunnels.yaml
     (install the local daemon as a boot-start OS service; then manage with
      calabi daemon {start|stop|status|restart|uninstall})
  calabi http <local-port> [--name NAME] [--domain DOMAIN]
  calabi tcp  <local-port> [--name NAME] [--remote-port N]
  calabi udp  <local-port> [--name NAME] [--remote-port N]
  calabi mesh {up|down|status}
     (switch the running daemon's mesh on or off — device to device over
      WireGuard; tunnels keep working either way. See "calabi mesh help".)
  calabi update [--check]
     (check for a new client version; install it when this machine can)
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
  CALABI_SERVER        calabi-edge host:port — pins the edge instead of
                       discovering it through your account (advanced)
  CALABI_API_KEY       API key (tk_…) for running tunnels; overrides creds file
  CALABI_TOKEN         legacy alias of CALABI_API_KEY (back-compat)
  CALABI_INSECURE      "1" to skip TLS verification (dev)
  CALABI_DEBUG        "1" for verbose logging
  CALABI_CONFIG        path to credentials file (default: per-OS config dir)
  CALABI_MODE          platform | standalone -- standalone: this client uses
                       the self-hosted server it joined, not calabi.net
                       (see "calabi mode")
  CALABI_UPDATE_MANIFEST
                       signed update-manifest URL, checked only by a
                       machine-wide service (daemon install --system);
                       set it EMPTY to disable the update check

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
	//
	// And when the console switches the daemon between calabi.net and a
	// self-hosted server (requestDaemonRestart): runDaemon then starts it again.
	go func() {
		select {
		case <-serviceStop:
			cancel()
		case <-restartCh:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

// edgeDiscoveryTimeout bounds the whole "ask bff-console which edge to dial"
// step for a one-shot command. edgepicker caps each /v1/edges query at 10s and
// can run two of them (region, then any-region) plus a token refresh; someone
// waiting at a prompt should not sit through all of that before being told what
// to fix. The daemon has no such budget — it retries forever — which is why the
// bound lives here and not in the picker.
const edgeDiscoveryTimeout = 20 * time.Second

// requireEdgeAddr returns the edge address for a one-shot tunnel command
// (`calabi http/tcp/udp/sni`), or "" after printing what to do about it.
//
// In order:
//
//  1. CALABI_SERVER, or an address baked in at build time. Explicit wins and
//     costs no round-trip: a dev stack, or a self-hosted build that names its
//     own edge, keeps dialling exactly that with no control plane involved.
//  2. Discovery through bff-console — the same edgepicker the daemon uses, with
//     the same credential, region preference and sticky edge.
//  3. Nothing to dial: say what to set.
//
// Step 2 is why this is not two lines. A platform RELEASE bakes the default
// EMPTY on purpose (clients discover their edge, and there is no single
// production edge to name — scripts/package-release-client.sh), so until
// discovery landed here every one of these commands ended at step 3 on an
// official binary. That includes `calabi login` followed by `calabi http 8080`,
// which is the first thing the docs teach. The daemon had discovery the whole
// time; these four commands simply never asked.
//
// Discovery sits BELOW the baked default here, where the daemon puts it above
// (there it is the last resort). Deliberate: this default is only ever
// non-empty because somebody chose to bake one, and letting a control-plane
// answer overrule that would change what dev and self-hosted builds dial today.
// Empty was the broken case; empty is the only case whose behaviour changes.
func requireEdgeAddr(logger *slog.Logger, cmd string) string {
	if addr := envOr("CALABI_SERVER", defaultServer); addr != "" {
		return addr
	}

	// No credential means no discovery AND no handshake: /v1/edges answers 401,
	// and the edge would refuse the session a second later anyway. Say the one
	// thing that fixes both, instead of reporting a lookup failure.
	tok, kind := resolveCredential()
	if kind == credDefault {
		fmt.Fprintf(os.Stderr, "calabi %s: not signed in.\n"+
			"  The edge to dial is discovered through your account, so sign in first:\n"+
			"    calabi login          (or set CALABI_API_KEY=tk_… for an unattended run)\n"+
			"  To dial an edge directly instead, set CALABI_SERVER=<edge-host>:7443.\n", cmd)
		return ""
	}

	// The daemon's preferences, READ-ONLY: persisting LastEdgeNodeID is the
	// daemon's job (runOneSession), and a 30-second `calabi http` must not
	// re-aim the installed service's next boot.
	//
	// TWO THINGS NAME A REGION AND THEY CARRY DIFFERENT FORCE.
	//
	//   EdgeRegion     — somebody CHOSE it (--edge-region --persist-edge-region,
	//                    or the console's region switcher). An instruction.
	//                    Honour it, and refuse rather than quietly use another.
	//   LastEdgeRegion — where the daemon last happened to connect. An
	//                    observation. The daemon LOCKS to it because it serves
	//                    tunnels that already exist, and per-edge wildcard DNS
	//                    means moving edge silently breaks their URLs.
	//
	// This command creates a NEW tunnel, with no URL to protect. Locking to the
	// anchor here buys nothing and costs everything: when the anchored region's
	// edge is briefly down — a self-hosted edge rebooting, say — the command
	// refuses to run at all while a healthy platform edge sits there ready to
	// serve it. So the anchor is a preference (try it first), never a lock.
	// That also matches how the OTHER preference already degrades: BYOI
	// ownership narrowing falls back to platform edges rather than strand you.
	var explicitRegion, anchorRegion string
	var stickyEdgeID int64
	var preferPlatformEdge bool
	if c, err := creds.Load(); err == nil && c != nil {
		explicitRegion, anchorRegion = c.EdgeRegion, c.LastEdgeRegion
		stickyEdgeID, preferPlatformEdge = c.LastEdgeNodeID, c.PreferPlatformEdge
	}
	explicitRegion = envOr("CALABI_EDGE_REGION", explicitRegion)
	region := explicitRegion
	if region == "" {
		region = anchorRegion
	}
	// CALABI_EDGE_AFFINITY overrides the persisted class for THIS RUN only.
	// The daemon's --edge-affinity also persists it and clears the edge anchor;
	// a one-shot command has no business doing either — same read-only posture
	// as the sticky edge above. Honouring the env at all is for consistency
	// with CALABI_EDGE_REGION, which is read the same way one line up.
	switch strings.ToLower(strings.TrimSpace(os.Getenv("CALABI_EDGE_AFFINITY"))) {
	case "platform":
		preferPlatformEdge = true
	case "own":
		preferPlatformEdge = false
	}

	ctx, cancel := context.WithTimeout(context.Background(), edgeDiscoveryTimeout)
	defer cancel()
	pick := edgepicker.Pick(ctx, logger, edgepicker.Input{
		Region: region,
		// Locked ONLY for a region somebody asked for. An anchor inherited from
		// the daemon is tried first and then fallen through — see above.
		RestrictToRegion:   explicitRegion != "",
		BFFConsoleURL:      bffURL(),
		AccessToken:        tok,
		StickyEdgeNodeID:   stickyEdgeID,
		PreferPlatformEdge: preferPlatformEdge,
		RefreshBearer:      refreshBearer,
		// DefaultAddr stays empty on purpose: we are here BECAUSE there is no
		// baked default. Handing Pick one would re-offer the address the first
		// line of this function already found empty.
	})
	if pick.Addr == "" {
		fmt.Fprintf(os.Stderr, "calabi %s: no edge address.\n"+
			"  Asked %s which edge to dial, and got none:\n"+
			"    %s\n"+
			"  Fix that, or set CALABI_SERVER=<edge-host>:7443 to dial an edge directly.\n",
			cmd, bffURL(), pick.Reason)
		if pick.RegionUnavailable {
			// Only reachable when the region was ASKED for, so name where the
			// ask came from — otherwise the user hunts for a setting they never
			// knowingly made.
			src := "your saved edge region"
			if os.Getenv("CALABI_EDGE_REGION") != "" {
				src = "CALABI_EDGE_REGION"
			}
			fmt.Fprintf(os.Stderr,
				"  (region %q comes from %s; set CALABI_EDGE_REGION=<other> for this run,\n"+
					"   or clear it to use any region with a healthy edge.)\n",
				pick.Region, src)
		}
		return ""
	}
	logger.Info("edge selected",
		"addr", pick.Addr, "region", pick.Region, "reason", pick.Reason,
		"edge_node_id", pick.EdgeNodeID)
	return pick.Addr
}
