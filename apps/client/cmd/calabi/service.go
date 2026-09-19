// service.go — `calabi daemon {install|uninstall|start|stop|restart|status}`.
//
// We wrap kardianos/service so a single calabi binary can install itself
// as a Windows Service, a systemd unit (system OR user), or a launchd
// agent on macOS, with the same UX everywhere:
//
//	calabi daemon install      # one-time setup; needs admin on win+linux
//	calabi daemon start        # ask the OS service manager to start us
//	calabi daemon stop         # ditto, stop
//	calabi daemon restart      # graceful: stop then start
//	calabi daemon status       # query the service manager
//	calabi daemon uninstall    # remove the service entry; safe to repeat
//
// When the OS service manager actually executes us (boot, manual start,
// crash-restart), the binary is invoked as `calabi daemon` (without
// install). kardianos detects the service context and dispatches into
// our serviceProgram.Run() which is just the regular runDaemon body
// minus the install/uninstall routing.
//
// Privilege model: install/uninstall need admin on Windows + Linux
// (writing to the registry / /etc/systemd/system). We don't sudo for
// the user — they get a clear error message and re-run with elevated
// shell. macOS launchd accepts user-level agents which is more sensible
// for a desktop daemon; the package picks UserService when available.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/calabi/calabi/apps/client/internal/creds"
	cruntime "github.com/calabi/calabi/apps/client/internal/runtime"
	"github.com/kardianos/service"
)

// serviceStatus reports whether the OS service is registered, and if so what
// state it is in. Any query error degrades to not-installed, so callers fall
// back to the transient-daemon path rather than wrongly suppressing it.
//
// It returns the STATUS, where the earlier serviceInstalled() threw it away and
// answered a plain bool. That loss is what made `calabi login` say "daemon runs
// as an installed service — start it if it isn't already": a hedge, written
// because the caller genuinely did not know, printed to somebody who had just
// established that nothing was running. We asked the service manager; there is
// no reason to pass the uncertainty on.
//
// NOTE the service name: resolveServiceName(nil) is the DEFAULT name (or
// CALABI_SERVICE_NAME). A service installed under --service-name is invisible
// here. That is a known, deliberate limit — see the note in runLogin.
func serviceStatus() (service.Status, bool) {
	if svc, err := buildService(nil, nil); err == nil {
		if st, installed := classifyServiceStatus(svc.Status()); installed {
			return st, true
		}
	}
	if macInstallerServicePresent(runtime.GOOS, macInstallerDaemonPlist) {
		return service.StatusUnknown, true
	}
	return service.StatusUnknown, false
}

// classifyServiceStatus turns a service manager's answer into (state, installed).
//
// "Not allowed to ask" is INSTALLED, state unknown. Windows answers a non-admin
// status query for the LocalSystem service with Access is denied (kardianos
// opens it asking for start/stop rights too), while a name that does not exist
// still comes back as not-installed — checked 2026-09-16 from a non-admin
// shell. Reading the refusal as not-installed is how `calabi login` came to
// start a second daemon next to the desktop app's service on every Windows
// install. Any other error still degrades to not-installed, as it always has,
// so a machine with no usable service manager keeps its transient daemon.
func classifyServiceStatus(st service.Status, err error) (service.Status, bool) {
	switch {
	case err == nil:
		return st, true
	case errors.Is(err, os.ErrPermission):
		return service.StatusUnknown, true
	default:
		return service.StatusUnknown, false // ErrNotInstalled / ErrServiceNotFound
	}
}

// macInstallerDaemonPlist is the LaunchDaemon the macOS installer registers —
// DAEMON_LABEL in scripts/package-macos-pkg.sh. The service library never finds
// it: it looks for a job named after resolveServiceName ("calabi"), and from a
// non-root shell only among LaunchAgents.
const macInstallerDaemonPlist = "/Library/LaunchDaemons/com.calabi.daemon.plist"

func macInstallerServicePresent(goos, plist string) bool {
	if goos != "darwin" {
		return false
	}
	_, err := os.Stat(plist)
	return err == nil
}

// serviceNote is what `calabi login` prints about an installed service when no
// console answered for it. Split out so the wording of each state is pinned by a
// test rather than by whoever reads the switch next.
//
// Whatever the state, the service keeps its OWN credential — a sign-in made in
// its console, or an API key — so this login is never "handed" to it. The old
// running line ("that is this machine's daemon") read as if it had been.
func serviceNote(st service.Status) string {
	switch st {
	case service.StatusRunning:
		return "  a calabi service is installed and running — it keeps its own sign-in, so this\n" +
			"  login is for commands run in this shell"
	case service.StatusStopped:
		// Nothing is serving, and the caller has already established that no
		// daemon of this client is either — so say so, and name both ways out.
		return "  a calabi service is installed but NOT running — start it with " +
			"`calabi daemon start`,\n  or run `calabi daemon` in this shell for this login"
	default:
		return "  a calabi service is installed (this shell is not allowed to ask whether it is\n" +
			"  running) — it keeps its own sign-in, so this login is for commands run in this shell"
	}
}

// joinServiceNote is what `calabi join` says when this computer has a calabi
// service installed. The service is another client with its own data: the join
// does not reach it, and starting it would not use the join. serviceNote, which
// join used to print, is written for login and says to start the service when
// it is stopped — which starts that OTHER client.
func joinServiceNote(st service.Status) string {
	state := "installed"
	switch st {
	case service.StatusRunning:
		state = "installed and running"
	case service.StatusStopped:
		state = "installed but not running"
	}
	return "  this computer also has a calabi service (" + state + "). It is a separate client\n" +
		"  with its own sign-in: this join does not reach it, and starting it does not use this join.\n" +
		"  to use this join:  calabi daemon   (in this shell; keep it open)\n" +
		"  to put the service on this server instead: join from its console (Settings → Connect)"
}

// reportDaemonStatus prints `calabi daemon status` from the service manager's
// answer (st, err). published is the console URL the service last wrote, if this
// shell can read it; candidates are where to look for a console when it cannot.
// (The macOS installer's service never gets here — see service_mac_installer.go.)
//
// A refusal to answer is not a failure to report. From a non-admin shell on
// Windows the service manager answers Access is denied for the installed
// service, and this used to print exactly that and exit 1 — on every desktop
// install, to the person the service was installed for. The service IS there;
// only its state is out of reach, and its console usually is not.
func reportDaemonStatus(ctx context.Context, stdout, stderr io.Writer, st service.Status, err error,
	published string, candidates []string) int {
	switch {
	case err == nil:
	case errors.Is(err, os.ErrPermission):
		fmt.Fprintln(stdout, "  installed — this shell is not allowed to query its state (an administrator shell can)")
		reportServiceConsole(ctx, stdout, published, candidates)
		return 0
	case errors.Is(err, service.ErrNotInstalled):
		// kardianos returns ErrNotInstalled / ErrServiceNotFound
		// depending on platform — both mean "service entry missing".
		fmt.Fprintln(stdout, "  not installed (run: calabi daemon install)")
		return 0
	default:
		fmt.Fprintln(stderr, "status:", err)
		return 1
	}
	switch st {
	case service.StatusRunning:
		fmt.Fprintln(stdout, "  running")
		// Show the console address — but only after confirming something
		// answers there. "a running service keeps it current" was the old
		// comment here and it is not true: a bind slower than the two
		// seconds startStatusPage waits never overwrote the file, so this
		// printed the PREVIOUS run's port (see publishConsoleURLLate).
		if published != "" {
			cctx, ccancel := context.WithTimeout(ctx, 2*time.Second)
			ok := consoleAnswers(cctx, consoleAddrOf(published, ""))
			ccancel()
			if ok {
				fmt.Fprintln(stdout, "  console: "+published)
			} else {
				fmt.Fprintln(stdout, "  console: not answering (last published: "+published+")")
			}
		}
	case service.StatusStopped:
		fmt.Fprintln(stdout, "  stopped")
	default:
		fmt.Fprintln(stdout, "  unknown")
	}
	return 0
}

// reportServiceConsole names the console for a service whose state could not be
// read: the one it published, when this shell can read that and it answers;
// otherwise every calabi console answering on this machine, with what each runs
// on. Nothing at all is printed when nothing answers — the state is unknown,
// and "not running" would be a guess.
func reportServiceConsole(ctx context.Context, w io.Writer, published string, candidates []string) {
	if published != "" {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		ok := consoleAnswers(cctx, consoleAddrOf(published, ""))
		cancel()
		if ok {
			fmt.Fprintln(w, "  console: "+published)
			return
		}
	}
	for _, c := range probeOtherClients(ctx, "", candidates) {
		how := "keeps its own sign-in"
		if c.Agent {
			how = "runs on an API key"
		}
		fmt.Fprintf(w, "  a calabi console is answering at http://%s (%s)\n", c.Addr, how)
	}
}

// publishedServiceConsoleURL is the console URL an installed service last
// wrote: next to the executable for a legacy Windows service, in the
// machine-wide data dir for a --system one. The second is often unreadable
// from a non-admin shell, which just leaves it out.
func publishedServiceConsoleURL() string {
	if u := awaitConsoleURL(time.Time{}, 0); u != "" {
		return u
	}
	return awaitConsoleURLIn(creds.SystemDataDir(), time.Time{}, 0)
}

// installedServiceNote is the whole of what login says once it has found an
// installed service: what each console answering on this machine runs on — the
// service's, in practice — and, when login would otherwise have started a
// daemon, that it did not and how to get one anyway.
func installedServiceNote(st service.Status, others []otherClient, wantedStart bool) string {
	var lines []string
	if len(others) == 0 {
		lines = append(lines, serviceNote(st))
	} else {
		for _, c := range others {
			if c.Agent {
				lines = append(lines, "  the calabi client at http://"+c.Addr+" runs on its own API key — this login\n"+
					"  does not change it")
			} else {
				lines = append(lines, "  the calabi client at http://"+c.Addr+" keeps its own sign-in — this login\n"+
					"  does not change it; to switch its account, sign in from that console")
			}
		}
		lines = append(lines, "  this login is for commands run in this shell")
	}
	// A stopped service with nothing answering already names `calabi daemon`.
	if wantedStart && (len(others) > 0 || st != service.StatusStopped) {
		lines = append(lines, "  not starting a second daemon next to it — run `calabi daemon` if you want\n"+
			"  one for this login too")
	}
	return strings.Join(lines, "\n")
}

// killDaemonOnStatusPort terminates the calabi daemon LISTENING on the status
// port (:7400), unless its pid is exceptPID. Returns true if it killed
// something.
//
// This is the single, robust mechanism for "make sure the port is free for the
// service": it targets whoever ACTUALLY owns the port — found via the OS, not a
// per-user pid file — so it works across the account/config-dir split between a
// login-spawned user daemon and an invisible SYSTEM service (the per-user flock
// is blind to the latter, which was why earlier attempts didn't close it).
//
// Safety: we only act when /healthz on :7400 answers (so the owner is a calabi
// daemon, not some unrelated process), and we never kill exceptPID (the service
// we're about to start) or ourselves.
func killDaemonOnStatusPort(exceptPID int) bool {
	addr := envOr("CALABI_STATUS_ADDR", defaultStatusAddr)
	if !daemonAlreadyRunning(addr) {
		return false // nothing calabi-shaped on :7400
	}
	pid, ok := pidOnPort(statusPort(addr)) // Windows: netstat (account-agnostic)
	if !ok {
		pid, ok = cruntime.ReadDaemonPID() // fallback (same-account; non-Windows)
	}
	if !ok || pid <= 0 || pid == os.Getpid() || (exceptPID > 0 && pid == exceptPID) {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	fmt.Printf("  stopping the daemon on :7400 (pid %d) so the service can own it…\n", pid)
	_ = proc.Kill()
	for i := 0; i < 25 && daemonAlreadyRunning(addr); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	return true
}

// stopTransientDaemon frees :7400 for the service by stopping whatever daemon
// holds it — EXCEPT the service itself (so a re-run while the service is up is a
// no-op). Called from install/start.
func stopTransientDaemon() {
	except := 0
	if pid, ok := serviceProcessPID("calabi"); ok {
		except = pid
	}
	killDaemonOnStatusPort(except)
}

// statusPort parses the port out of a "host:port" status address; 7400 if it
// can't (the default).
func statusPort(addr string) int {
	if _, p, err := net.SplitHostPort(addr); err == nil {
		if n, err := strconv.Atoi(p); err == nil {
			return n
		}
	}
	return 7400
}

// serviceStop is closed by serviceProgram.Stop when the OS service manager asks
// us to shut down. The daemon body's withSignalContext (main.go) also cancels on
// this, so a graceful stop works even on Windows — where a session-0 service has
// no console and os.Interrupt can't be delivered to ourselves.
var (
	serviceStop     = make(chan struct{})
	serviceStopOnce sync.Once
)

// runDaemonService routes to install/uninstall/start/stop/etc. Called
// from runDaemon before flag parsing so `calabi daemon start` doesn't
// race the flag set.
func runDaemonService(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "calabi daemon: missing subcommand")
		return 2
	}
	sub := args[0]

	// The macOS installer's LaunchDaemon, which the service library cannot reach
	// (see service_mac_installer.go). Checked before install's credential step:
	// on such a machine nothing is going to be installed.
	if drivesMacInstallerService(runtime.GOOS, args[1:], macInstallerDaemonPlist) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return newMacInstallerService(geteuid(), os.Stdout, os.Stderr).run(ctx, sub)
	}

	// On install, provision a credential the service can use. The service runs
	// in a DIFFERENT OS account than your interactive shell (LocalSystem on
	// Windows, root under systemd), so it can't see the login you saved in your
	// own profile. serviceInstallEnv resolves/mints a long-lived API key (and
	// carries your region/affinity) and we bake it into the service env so it
	// connects on boot without any manual step. Only install needs this — the
	// other subcommands operate on the already-registered service.
	var extraEnv map[string]string
	if sub == "install" {
		e, perr := serviceInstallEnv(args[1:])
		if perr != nil {
			fmt.Fprintln(os.Stderr, "calabi daemon install:", perr)
			return 1
		}
		extraEnv = e
		// Pin the local console address for THIS service. It is otherwise decided
		// at runtime (the daemon scans from :7400 for a free port), which is
		// nondeterministic across restarts and invisible unless you read the log.
		// Either flag bakes a fixed CALABI_STATUS_ADDR into the service env so
		// each service client owns a known address; the runtime still shifts to
		// the next free port if that one is busy.
		//
		// --status-addr is the full address and matches the flag on `calabi
		// daemon`. --status-port is the older port-only form, kept working; if
		// both are given the more specific one wins.
		if sa := strings.TrimSpace(extractFlagValue(args[1:], "status-addr")); sa != "" {
			warning, serr := applyStatusAddr(sa)
			if serr != nil {
				fmt.Fprintln(os.Stderr, "calabi daemon install:", serr)
				return 1
			}
			if warning != "" {
				fmt.Fprintln(os.Stderr, "calabi daemon install: warning:", warning)
			}
			if extraEnv == nil {
				extraEnv = map[string]string{}
			}
			extraEnv["CALABI_STATUS_ADDR"] = sa
		} else if pr := strings.TrimSpace(extractFlagValue(args[1:], "status-port")); pr != "" {
			if _, err := strconv.Atoi(pr); err != nil {
				fmt.Fprintf(os.Stderr, "calabi daemon install: --status-port must be a number, got %q\n", pr)
				return 1
			}
			if extraEnv == nil {
				extraEnv = map[string]string{}
			}
			extraEnv["CALABI_STATUS_ADDR"] = "127.0.0.1:" + pr
		}
	}

	svc, err := buildService(args[1:], extraEnv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi daemon:", err)
		return 1
	}
	// A NAMED (non-default) service is a deliberate second-client-on-this-machine
	// install. It must NOT reap whatever holds :7400 — that would kill a sibling
	// client's daemon. Named services coexist via the :7400 port fallback, so the
	// transient-daemon / port-reaping coordination only applies to the default
	// "calabi" service.
	name := resolveServiceName(args[1:])
	isDefault := name == defaultServiceName
	// Suffix the management commands we print with --service-name for a named
	// service, so the user knows how to drive THIS one.
	nameFlag := ""
	if !isDefault {
		nameFlag = " --service-name " + name
	}
	switch sub {
	case "install":
		// A machine-wide service registers with launchd's system domain /
		// /etc/systemd/system — root only. Fail fast with a clear message rather
		// than a cryptic permission error from the service manager. (Windows
		// elevation is surfaced by explainInstallErr below.)
		if hasBoolFlag(args[1:], "system") && runtime.GOOS != "windows" && os.Geteuid() != 0 {
			fmt.Fprintln(os.Stderr, "install --system: a machine-wide service must be installed as root — re-run with sudo.")
			return 1
		}
		if err := svc.Install(); err != nil {
			fmt.Fprintln(os.Stderr, "install:", explainInstallErr(err))
			return 1
		}
		// The service is now the canonical daemon — retire the login-spawned
		// one so it doesn't keep :7400 and this account's tunnel claims when the
		// service starts. Default service only (see above).
		if isDefault {
			stopTransientDaemon()
		}
		startCmd := "calabi daemon start" + nameFlag
		if hasBoolFlag(args[1:], "system") && runtime.GOOS != "windows" {
			// A system service (root LaunchDaemon / systemd system unit) is managed
			// as root — mirror that in the hint so start/stop hit the same domain.
			startCmd = "sudo " + startCmd
		}
		fmt.Printf("  installed (service %q). start with:  %s\n", name, startCmd)
		fmt.Printf("  console: %s  (shifts to the next free port if busy — see the service log for the actual one)\n",
			installStatusURL(args[1:]))
		// Last, so it is the thing still on screen: the unit is written and looks
		// fine, but on an SELinux host it may point at a binary the service domain
		// cannot execute. No-op on every other OS.
		warnIfServiceCannotExec()
		return 0
	case "uninstall":
		// Try to stop first — uninstall on a running service fails on
		// systemd ("unit is loaded") and Windows ("MarkedForDeletion").
		_ = svc.Stop()
		if err := svc.Uninstall(); err != nil {
			fmt.Fprintln(os.Stderr, "uninstall:", err)
			return 1
		}
		// Reap any daemon that survived on :7400 — e.g. an older registered
		// binary whose Stop was a no-op, now an invisible SYSTEM orphan. The
		// service entry is gone, so no recovery action resurrects it. (0 = no
		// pid to spare; kill whoever still holds the port.) Default service only:
		// a named service may bind a fallback port and isn't tied to :7400, and
		// reaping :7400 here could kill a sibling client.
		if isDefault {
			killDaemonOnStatusPort(0)
		}
		fmt.Println("  uninstalled.")
		return 0
	case "start":
		// A login-spawned daemon would compete with the service for :7400 and
		// this account's tunnel claims — stop it first so the service is the
		// single daemon. Default service only (a named service coexists).
		if isDefault {
			stopTransientDaemon()
		}
		startedAt := time.Now()
		if err := svc.Start(); err != nil {
			fmt.Fprintln(os.Stderr, "start:", err)
			return 1
		}
		fmt.Println("  start requested.")
		printConsoleHint(startedAt)
		return 0
	case "stop":
		if err := svc.Stop(); err != nil {
			fmt.Fprintln(os.Stderr, "stop:", err)
			return 1
		}
		fmt.Println("  stop requested.")
		return 0
	case "restart":
		_ = svc.Stop()
		if isDefault {
			stopTransientDaemon()
		}
		startedAt := time.Now()
		if err := svc.Start(); err != nil {
			fmt.Fprintln(os.Stderr, "restart:", err)
			return 1
		}
		fmt.Println("  restart requested.")
		printConsoleHint(startedAt)
		return 0
	case "status":
		st, err := svc.Status()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return reportDaemonStatus(ctx, os.Stdout, os.Stderr, st, err,
			publishedServiceConsoleURL(), otherConsoleCandidates())
	}
	fmt.Fprintf(os.Stderr, "calabi daemon: unknown subcommand %q\n", sub)
	return 2
}

// defaultServiceName is the OS service id used when --service-name isn't given.
// Keeping it "calabi" preserves single-install back-compat.
const defaultServiceName = "calabi"

// resolveServiceName picks the OS service id for this invocation. Precedence:
//
//	--service-name flag  →  CALABI_SERVICE_NAME env  →  "calabi" (default).
//
// The env fallback is how a service launched by the SCM/systemd learns its OWN
// name: install bakes CALABI_SERVICE_NAME into the service env
// buildService), so the in-service Run path — which calls buildService(nil,nil)
// with no args — resolves the same name the install used, and the control
// dispatcher matches. Letting users name services is what allows several
// service-installed clients on one machine (calabi-client1, calabi-client2, …),
// each in its own dir (its own creds/pid/port via the per-dir data dir + the
// :7400 port fallback).
func resolveServiceName(args []string) string {
	if v := strings.TrimSpace(extractFlagValue(args, "service-name")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("CALABI_SERVICE_NAME")); v != "" {
		return v
	}
	return defaultServiceName
}

// installStatusURL is the console URL we PRINT at install — the intended
// address, from --status-port, else a CALABI_STATUS_ADDR in the install shell,
// else the :7400 default. (The actual bound port is resolved at runtime and may
// shift on a conflict; the daemon logs the real one.)
func installStatusURL(installArgs []string) string {
	if a := strings.TrimSpace(extractFlagValue(installArgs, "status-addr")); a != "" {
		if strings.EqualFold(a, "disabled") || strings.EqualFold(a, "off") {
			return ""
		}
		return "http://" + a
	}
	if p := strings.TrimSpace(extractFlagValue(installArgs, "status-port")); p != "" {
		return "http://127.0.0.1:" + p
	}
	if a := strings.TrimSpace(os.Getenv("CALABI_STATUS_ADDR")); a != "" {
		return "http://" + a
	}
	return "http://" + defaultStatusAddr
}

// awaitConsoleURL reads the console URL the daemon publishes to its data dir.
// `calabi daemon start` runs in a SEPARATE process from the detached service
// (which is where the daemon's startup banner prints), so it can't see the real
// bound port directly — it reads it from <exe-dir>/console.url, the service's
// data dir (creds.SetDataDir(exeDir) under the service manager). Polls up to
// `timeout` for a FRESH value (mtime after `since`); on timeout returns a stale
// value if one exists (better than nothing — usually the same port).
func awaitConsoleURL(since time.Time, timeout time.Duration) string {
	return awaitConsoleURLIn(exeDir(), since, timeout)
}

// awaitConsoleURLIn is awaitConsoleURL against an explicit data dir. The
// service publishes next to the exe; an interactive daemon publishes into the
// per-user data dir (creds.DataDir), and `calabi login` needs THAT one — asking
// the port instead would read back whichever client happens to hold :7400.
func awaitConsoleURLIn(dir string, since time.Time, timeout time.Duration) string {
	return awaitConsoleURLInAny([]string{dir}, since, timeout)
}

// awaitConsoleURLInAny is awaitConsoleURLIn over several candidate data dirs:
// the first fresh value in any of them, else a stale one.
func awaitConsoleURLInAny(dirs []string, since time.Time, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	var stale string
	for {
		for _, dir := range dirs {
			if dir == "" {
				continue
			}
			p := filepath.Join(dir, consoleURLFile)
			if b, err := os.ReadFile(p); err == nil {
				if u := strings.TrimSpace(string(b)); u != "" {
					if fi, e2 := os.Stat(p); e2 == nil && fi.ModTime().After(since.Add(-3*time.Second)) {
						return u // fresh — this run's bind
					}
					if stale == "" {
						stale = u
					}
				}
			}
		}
		if time.Now().After(deadline) {
			return stale
		}
		time.Sleep(150 * time.Millisecond)
	}
}

// printConsoleHint prints the console URL after a start, or that it is still
// coming when the daemon hasn't published it yet. It looks where a service keeps
// its data — next to its exe, or the machine-wide dir — and the service's exe
// need not be this one: `calabi daemon start` run from another copy starts the
// INSTALLED service, and this copy's directory used to be named as where its log
// would be.
func printConsoleHint(since time.Time) {
	if url := awaitConsoleURLInAny([]string{exeDir(), creds.SystemDataDir()}, since, 5*time.Second); url != "" {
		fmt.Println("  console: " + url)
		return
	}
	fmt.Println("  console: starting — `calabi daemon status` shows its address in a moment")
}

// buildService wraps the kardianos service.Config + program shim.
// Picks UserService on macOS where launchd LaunchAgents (per-user)
// avoid sudo. On Windows + Linux we install as a system service
// because user-level systemd is a footgun (different default targets).
//
// installArgs are the flags that followed the subcommand (e.g. the
// `--config tunnels.yaml` in `calabi daemon install --config …`). They decide
// what command the installed service launches at boot — see serviceArguments.
//
// extraEnv (install only) carries the service credential resolved by
// serviceInstallEnv — CALABI_API_KEY plus the user's region/affinity — so the
// service authenticates without the user's profile. It overrides any same-named
// var from the shell. nil for non-install callers and the SCM Run path.
// geteuid is os.Geteuid, overridable in tests. Returns -1 on Windows.
var geteuid = os.Geteuid

func buildService(installArgs []string, extraEnv map[string]string) (service.Service, error) {
	prog := &serviceProgram{}
	return service.New(prog, serviceConfig(installArgs, extraEnv))
}

// serviceConfig builds the kardianos service.Config (pure — no service.New) so
// the install-time wiring is unit-testable: service name, per-service env, and
// the Option-A system-vs-user switch.
func serviceConfig(installArgs []string, extraEnv map[string]string) *service.Config {
	// All three service managers honor per-service env vars: systemd writes
	// Environment= into the unit, launchd an EnvironmentVariables dict, and
	// Windows a REG_MULTI_SZ "Environment" value under the service key (SCM
	// injects it at start — kardianos v1.2.2 does this; an older note that
	// "Windows ignores" EnvVars was wrong).
	// Resolve --system before the passthrough: a production privileged service must
	// not inherit a stray dev CALABI_INSECURE (see filterCalabiEnv).
	systemMode := hasBoolFlag(installArgs, "system")
	env := passthroughEnv(systemMode)
	for k, v := range extraEnv {
		env[k] = v
	}
	// Path-valued env vars MUST be absolute: the service starts from a different
	// working directory (C:\Windows\System32 on Windows; / under systemd), so a
	// relative CALABI_EDGE_CA_FILE / CALABI_CONFIG inherited from the install
	// shell silently fails to resolve at boot — e.g. a dev edge CA at
	// "deploy/dev/certs/ca.crt" becomes "cannot find the path", the TLS dial
	// fails, and the daemon reconnects forever. Resolve against the install
	// shell's cwd (where these paths were meant to be relative to).
	for _, k := range []string{"CALABI_EDGE_CA_FILE", "CALABI_CONFIG"} {
		if v := env[k]; v != "" && !filepath.IsAbs(v) {
			if abs, err := filepath.Abs(v); err == nil {
				env[k] = abs
			}
		}
	}
	// HOME, on the platforms whose service managers do not provide one.
	//
	// systemd starts a unit with a nearly empty environment and no HOME; launchd
	// is no better. The client resolves its credentials through
	// XDG_CONFIG_HOME/HOME (creds.configDir), so without this the installed
	// service cannot read the file `calabi login` just wrote — it fails with
	// "$HOME is not defined", enrols without its device fingerprint, and the
	// console cannot link the node to its client record.
	//
	// Only the Windows SCM path pins the data dir next to the exe
	// (runDaemonBody), and only a --system install carries the machine-wide
	// marker; a plain `daemon install` on Linux has neither, which is exactly the
	// case that broke. Baking the INSTALLING user's HOME keeps the service
	// reading the same credentials that user logged in with — the continuity a
	// relocation would break for every existing install.
	applyServiceHome(env, runtime.GOOS, userHomeDir())
	name := resolveServiceName(installArgs)
	// Bake the name into the service env so the in-service Run path (which calls
	// buildService(nil,nil)) resolves the same name and the control dispatcher
	// matches. EnvVars only takes effect at Install; harmless for other callers.
	env["CALABI_SERVICE_NAME"] = name
	// Option A (privileged system service): `--system` installs a machine-wide
	// service (root LaunchDaemon / LocalSystem / systemd system unit) instead of a
	// per-user agent. Bake a marker so the boot path (applySystemServiceDataDir,
	// via the shared maybeRunUnderServiceManager chokepoint — reached on every
	// platform) anchors the data dir at the machine-wide SystemDataDir.
	if systemMode {
		env["CALABI_SYSTEM_SERVICE"] = "1"
	}
	display := "Calabi Tunnel Client"
	if name != defaultServiceName {
		display = "Calabi Tunnel Client (" + name + ")"
	}
	cfg := &service.Config{
		Name:        name,
		DisplayName: display,
		Description: "Calabi tunnel daemon — keeps the local client online + auto-claims console-pushed tunnels.",
		Arguments:   serviceArguments(installArgs),
		EnvVars:     env,
		// Auto-restart the daemon if it exits abnormally, so "install as a
		// service" keeps tunnels online across a crash/OOM — not just across
		// reboots. Each service manager reads the key that applies to it:
		//   • Windows SCM → Option["OnFailure"]="restart" wires SCM recovery
		//     actions. WITHOUT it kardianos sets NONE (a crashed service stays
		//     dead) — this is the gap this closes.
		//   • systemd → already defaults to Restart=always (kardianos), so
		//     OnFailure is ignored here.
		//   • launchd → already KeepAlive=true, so OnFailure is ignored here.
		Option: service.KeyValue{
			"OnFailure":              "restart",
			"OnFailureDelayDuration": "5s",
		},
	}
	// macOS launchd splits by privilege: root manages /Library/LaunchDaemons, a
	// normal user ~/Library/LaunchAgents. Drive UserService off euid (NOT the
	// --system flag) so install AND the later start/stop/status/uninstall target
	// the SAME domain without repeating a flag — you already need sudo to manage a
	// system daemon, and launchctl refuses a LaunchAgents path when run as root.
	// (--system still bakes the SystemDataDir marker above; the preflight in
	// runDaemonService keeps --system installs root so this lands on a Daemon.)
	if runtime.GOOS == "darwin" && geteuid() != 0 {
		cfg.Option["UserService"] = true
	}
	return cfg
}

// hasBoolFlag reports whether a bare boolean flag (--name / -name, or the
// explicit =true form) appears in a raw arg slice. Like extractFlagValue it
// scans leniently rather than using a FlagSet, so it composes with the other
// install flags the daemon-service path pulls out by hand.
func hasBoolFlag(args []string, name string) bool {
	dd, sd := "--"+name, "-"+name
	for _, a := range args {
		if a == dd || a == sd || a == dd+"=true" || a == sd+"=true" {
			return true
		}
	}
	return false
}

// serviceArguments computes the command-line the OS service manager launches
// the binary with at boot. When `calabi daemon install` carried a local-daemon
// config (`--config tunnels.yaml`), the installed service runs the LOCAL
// supervisor — `daemon --local --config <abs path>` — resolved to an ABSOLUTE
// path because the service manager starts us from a different working directory
// (a relative path would silently fail at boot). Without a config it runs the
// bare platform daemon (`daemon`), the behaviour.
func serviceArguments(installArgs []string) []string {
	cfgPath := extractFlagValue(installArgs, "config")
	if cfgPath == "" {
		return []string{"daemon"}
	}
	if abs, err := filepath.Abs(cfgPath); err == nil {
		cfgPath = abs
	}
	return []string{"daemon", "--local", "--config", cfgPath}
}

// extractFlagValue pulls `--name value` / `--name=value` (also single-dash
// forms) out of a raw arg slice without a full flag.FlagSet parse — we only
// need one value and the slice still carries the subcommand-stripped tail.
// Returns "" when the flag is absent.
func extractFlagValue(args []string, name string) string {
	dd, sd := "--"+name, "-"+name
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == dd || a == sd:
			if i+1 < len(args) {
				return args[i+1]
			}
		case strings.HasPrefix(a, dd+"="):
			return strings.TrimPrefix(a, dd+"=")
		case strings.HasPrefix(a, sd+"="):
			return strings.TrimPrefix(a, sd+"=")
		}
	}
	return ""
}

// serviceProgram is the kardianos shim. Start/Stop must return quickly
// (the service manager kills us if Start takes too long), so we spawn
// a goroutine and stash the cancel func.
type serviceProgram struct {
	doneCh chan struct{}
}

func (p *serviceProgram) Start(s service.Service) error {
	p.doneCh = make(chan struct{})
	// runDaemon parses flags from os.Args[2:]. When the service manager
	// invokes us with Arguments=["daemon"], os.Args is [calabi, daemon].
	// runDaemon's flag set gets an empty slice — exactly what we want.
	go func() {
		code := runDaemonBody(os.Args[2:])
		_ = code // service manager doesn't surface our exit code
		close(p.doneCh)
	}()
	return nil
}

func (p *serviceProgram) Stop(s service.Service) error {
	// Cancel the daemon directly rather than via an OS signal: on Windows a
	// service has no console, and (*os.Process).Signal(os.Interrupt) on self is
	// unsupported there, so the old self-SIGINT was a silent no-op and Stop
	// hung. Closing serviceStop cancels the daemon body's context
	// withSignalContext), and its deferred lock.Release then cleans up.
	serviceStopOnce.Do(func() { close(serviceStop) })
	<-p.doneCh
	return nil
}

// runDaemonBody is the original runDaemon split out so serviceProgram
// can invoke it without re-entering the install/uninstall router.
// runDaemon itself stays a thin wrapper that does the routing + calls
// this when there's no service subcommand.
//
// Implementation: we DON'T duplicate the body — runDaemon calls into
// itself with a sentinel-free arg slice, and the install switch sees
// nothing matching and falls through to the boot path. To avoid
// recursion we use a package-level guard (read by
// maybeRunUnderServiceManager).
var inServiceManager bool

func runDaemonBody(args []string) int {
	inServiceManager = true
	// A --system service uses the machine-wide SystemDataDir (also set earlier in
	// maybeRunUnderServiceManager; idempotent). A legacy Windows service instead
	// pins data next to the exe — the SYSTEM account's %LOCALAPPDATA% resolves to
	// the unreadable …\config\systemprofile\AppData\Local\calabi, where the log
	// already goes.
	applySystemServiceDataDir()
	if os.Getenv("CALABI_SYSTEM_SERVICE") != "1" {
		if dir := exeDir(); dir != "" {
			creds.SetDataDir(dir)
		}
	}
	return runDaemon(args)
}

// exeDir is the directory of the running executable, or "" if it can't be
// resolved. Used to anchor a service's data files next to its binary.
func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Dir(exe)
}

// applySystemServiceDataDir points the data dir at the machine-wide SystemDataDir
// when the CALABI_SYSTEM_SERVICE marker is set — i.e. this process is a --system
// service (Option A). It's called from the shared boot chokepoint so it applies
// on launchd / systemd (which start the daemon directly and never reach the
// Windows-only serviceProgram path) as well as Windows. No-op otherwise.
func applySystemServiceDataDir() {
	if os.Getenv("CALABI_SYSTEM_SERVICE") == "1" {
		creds.SetDataDir(creds.SystemDataDir())
	}
}

// maybeRunUnderServiceManager bridges a Windows Service Control Manager (SCM)
// launch into the kardianos service-control dispatcher. Both runDaemon variants
// (platform and self-hosted alike) call it right after their subcommand routing.
//
// Why it's needed: `calabi daemon install` registers a Windows service whose
// binPath is `calabi.exe daemon …`. When SCM starts it, the process MUST connect
// back to the SCM control pipe — via StartServiceCtrlDispatcher, which kardianos
// calls inside svc.Run — and report SERVICE_RUNNING within the start timeout. A
// plain console daemon that skips this never connects, so SCM gives up with
// error 1053: "the service did not respond to the start or control request in a
// timely fashion" ("等待 … 服务的连接超时(120000 毫秒)"). systemd and launchd have
// no such handshake, which is why the direct boot path is fine there.
//
// Returns handled=false (caller continues with its in-process boot) on every
// non-Windows OS, on an interactive/console run, and on the re-entrant call from
// serviceProgram.Start (guarded by inServiceManager) — so the real daemon body
// still runs exactly once, inside prog.Start.
//
// service.Interactive() is false ONLY under the SCM: kardianos v1.2.2 derives it
// from x/sys/windows/svc.IsWindowsService(), so a daemon spawned by a console or
// by the desktop supervisor (not a registered service) is left untouched.
func maybeRunUnderServiceManager() (handled bool, code int) {
	// A --system service anchors its data machine-wide on EVERY platform. This is
	// the one chokepoint both runDaemon variants hit before boot, and launchd /
	// systemd start the daemon directly (never reaching the serviceProgram path
	// below), so the marker MUST be honored here — not just in runDaemonBody,
	// which only the Windows SCM path reaches.
	applySystemServiceDataDir()
	if runtime.GOOS != "windows" || inServiceManager || service.Interactive() {
		return false, 0
	}
	svc, err := buildService(nil, nil) // Arguments/EnvVars unused by Run; Name must match the installed service
	if err != nil {
		// Last resort: fall back to a direct run rather than failing to boot.
		// SCM may still time out, but a daemon started another way keeps working.
		fmt.Fprintln(os.Stderr, "calabi daemon: service wrapper:", err)
		return false, 0
	}
	if rerr := svc.Run(); rerr != nil {
		fmt.Fprintln(os.Stderr, "calabi daemon: service run:", rerr)
		return true, 1
	}
	return true, 0
}

// clientIgnoredEnv are CALABI_* vars a client daemon never reads — a server store
// DSN and a dev source-tree binary path — that only reach the environment through
// scripts/dev/run.ps1. They are pure leakage in an installed service, so the
// passthrough always drops them.
var clientIgnoredEnv = map[string]bool{
	"CALABI_DB_DSN":      true, // server/store DSN; a client daemon has no database
	"CALABI_DAEMON_PATH": true, // dev source-tree binary path (run.ps1)
}

// passthroughEnv copies the CALABI_* vars from the current environment into the
// service config so a user-set var (e.g. CALABI_BFF_CONSOLE / CALABI_EDGE_CA_FILE)
// survives the service-manager handoff. Real secrets live in the creds file, not
// here. systemService is the Option-A --system switch; see filterCalabiEnv for
// what it drops.
func passthroughEnv(systemService bool) map[string]string {
	return filterCalabiEnv(os.Environ(), systemService)
}

// filterCalabiEnv keeps the CALABI_* entries of environ for the service handoff,
// dropping the ones that must not ride into an installed service:
//
//   - clientIgnoredEnv (server/dev-only vars the client never reads), always;
//   - CALABI_INSECURE on a --system install. A production privileged service must
//     NEVER dial the control plane in plaintext. A stray dev CALABI_INSECURE=1
//     (scripts/dev/run.ps1 tells you to `setx CALABI_INSECURE 1`, which persists at
//     the USER level) would otherwise ride the passthrough into the install and
//     make the daemon dial the TLS coordinator in plaintext — every mesh register
//     then fails with "error reading server preface: EOF" and the node never gets
//     an overlay IP, while the more tolerant edge :7443 session still comes up, so
//     the cause looks like anything but this. A non-system (dev) install keeps it:
//     a local dev stack serves plaintext and needs it.
func filterCalabiEnv(environ []string, systemService bool) map[string]string {
	out := map[string]string{}
	for _, e := range environ {
		for i := 0; i < len(e); i++ {
			if e[i] == '=' {
				key := e[:i]
				if hasPrefix(key, "CALABI_") && !clientIgnoredEnv[key] &&
					!(systemService && key == "CALABI_INSECURE") {
					out[key] = e[i+1:]
				}
				break
			}
		}
	}
	return out
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }

// explainInstallErr converts the most common permission failure into a
// human hint. kardianos surfaces "access is denied" / "permission denied"
// — neither tells the user to elevate.
// runningInContainer reports whether we're executing inside a container, where
// there is no OS service manager to install into — the container runtime IS the
// supervisor, so `daemon install` is meaningless and fails with errors like
// `open /etc/init.d/calabi: no such file or directory`. Our own image sets
// CALABI_IN_CONTAINER=1; we also sniff the usual Docker / Kubernetes / LXC
// markers so a hand-rolled image is handled too.
func runningInContainer() bool {
	// Explicit override wins both ways: "1"/"true" forces on, "0"/"false" forces
	// off (escape hatch for a containerized host where you really do want the
	// service path, and it keeps detection deterministic).
	switch v := strings.TrimSpace(os.Getenv("CALABI_IN_CONTAINER")); {
	case v == "1" || strings.EqualFold(v, "true"):
		return true
	case v == "0" || strings.EqualFold(v, "false"):
		return false
	}
	if runtime.GOOS != "linux" {
		return false
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if b, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(b)
		if strings.Contains(s, "docker") || strings.Contains(s, "kubepods") ||
			strings.Contains(s, "containerd") || strings.Contains(s, "/lxc/") {
			return true
		}
	}
	return false
}

// containerizeDaemonArgs adapts the `daemon {install|start|restart|stop|…}`
// subcommands for a container. A container is its own supervisor, so installing
// an OS service is both impossible (no init system) and pointless. Instead we
// run the daemon in the FOREGROUND — the container restarts it on exit:
//
//   - install / start / restart: carry the install-only flags people pass
//     (--api-key, --status-port) into the env the foreground daemon reads, then
//     strip the subcommand so the caller falls through to the foreground daemon.
//   - stop / uninstall / status: there's no OS service to act on — print a
//     one-liner and tell the caller to return.
//
// Returns (newArgs, handled, code): handled=true ⇒ caller should `return code`
// now; otherwise it continues with newArgs. A no-op outside a container.
func containerizeDaemonArgs(args []string) (newArgs []string, handled bool, code int) {
	if len(args) == 0 || !runningInContainer() {
		return args, false, 0
	}
	switch args[0] {
	case "install", "start", "restart":
		rest := args[1:]
		if k := strings.TrimSpace(extractFlagValue(rest, "api-key")); k != "" {
			_ = os.Setenv("CALABI_API_KEY", k)
		}
		if p := strings.TrimSpace(extractFlagValue(rest, "status-port")); p != "" {
			_ = os.Setenv("CALABI_STATUS_ADDR", "127.0.0.1:"+p)
		}
		fmt.Fprintln(os.Stderr,
			"calabi daemon: container detected — a container supervises its own process, so there is no "+
				"OS service to install. Running `calabi daemon` in the foreground instead "+
				"(authenticate with CALABI_API_KEY or --api-key). Tip: set the image's default command to "+
				"`daemon` and pass -e CALABI_API_KEY=tk_….")
		return foregroundDaemonArgs(rest), false, 0
	case "stop", "uninstall":
		fmt.Fprintln(os.Stderr,
			"calabi daemon "+args[0]+": container detected — there is no OS service here. "+
				"Stop or remove the container itself.")
		return args, true, 0
	case "status":
		fmt.Fprintln(os.Stderr,
			"calabi daemon status: container detected — the daemon runs in the foreground (no OS service). "+
				"Inspect it with your container runtime (docker ps / kubectl).")
		return args, true, 0
	}
	return args, false, 0
}

// foregroundDaemonArgs rebuilds the arg list for a foreground `calabi daemon`
// from a service subcommand's flags, keeping ONLY the flags the foreground
// daemon's flagset understands — so it doesn't choke on the install-only
// --api-key / --status-port / --service-name (those are translated to env in
// containerizeDaemonArgs).
func foregroundDaemonArgs(rest []string) []string {
	var out []string
	for _, name := range []string{"name", "edge-region", "edge-affinity"} {
		if v := strings.TrimSpace(extractFlagValue(rest, name)); v != "" {
			out = append(out, "--"+name, v)
		}
	}
	return out
}

func explainInstallErr(err error) string {
	msg := err.Error()
	switch runtime.GOOS {
	case "windows":
		if containsAny(msg, "Access is denied", "access is denied", "permission") {
			return msg + " — re-run from an Administrator PowerShell."
		}
	case "linux":
		if containsAny(msg, "permission denied") {
			return msg + " — re-run with sudo, or use a user-level systemd unit (set $XDG_RUNTIME_DIR + run as your user)."
		}
	}
	return msg
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
	}
	return false
}

// applyServiceHome gives the installed service a HOME on the platforms whose
// service manager does not provide one. Pure (goos and home are passed in) so it
// is tested on the machine we develop on, not only on the one it matters for.
//
// An existing HOME in env is left alone: it came from the install shell through
// the passthrough and is a deliberate choice.
func applyServiceHome(env map[string]string, goos, home string) {
	if goos == "windows" || home == "" || env["HOME"] != "" {
		return
	}
	env["HOME"] = home
}

func userHomeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return h
}
