// service_mac_installer.go — `calabi daemon …` for the service the macOS
// installer registers.
//
// The installer (scripts/package-macos-pkg.sh) registers a root LaunchDaemon
// labelled com.calabi.daemon. The service library behind every other platform
// cannot reach it: it names the job after the service name ("calabi"), so it
// only ever loads and unloads /Library/LaunchDaemons/calabi.plist (or, without
// sudo, ~/Library/LaunchAgents/calabi.plist) — a file that does not exist. So
// on a machine set up by the installer, start / stop / restart / uninstall
// never touched the service, and install would have registered a SECOND root
// daemon over the same machine-wide data dir. The desktop app's tray told its
// users to run exactly those commands.
//
// Here the default-name subcommands drive the installer's job directly, with
// the launchctl verbs the installer's own postinstall and the packaging runbook
// use. A --service-name install is a separate
// client by design and keeps the ordinary path.
package main

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/creds"
)

const macInstallerDaemonLabel = "com.calabi.daemon"

// macInstallerService drives the installer's LaunchDaemon. launchctl runs the
// real binary in production and a fake in tests; it returns the command's
// combined output, and an error when it exits non-zero (the modern verbs used
// here — print, bootstrap, bootout, kickstart, enable — do report failure that
// way, unlike the legacy load/unload).
type macInstallerService struct {
	euid       int
	launchctl  func(args ...string) (string, error)
	stdout     io.Writer
	stderr     io.Writer
	consoleURL func(since time.Time, timeout time.Duration) string
	candidates []string
}

func newMacInstallerService(euid int, stdout, stderr io.Writer) *macInstallerService {
	return &macInstallerService{
		euid: euid,
		launchctl: func(args ...string) (string, error) {
			out, err := exec.Command("launchctl", args...).CombinedOutput()
			return strings.TrimSpace(string(out)), err
		},
		stdout: stdout,
		stderr: stderr,
		consoleURL: func(since time.Time, timeout time.Duration) string {
			return awaitConsoleURLIn(creds.SystemDataDir(), since, timeout)
		},
		candidates: otherConsoleCandidates(),
	}
}

// drivesMacInstallerService: the installer's plist is on disk and the command
// names no other service. A --service-name command is about a deliberately
// separate client and goes through the ordinary path.
func drivesMacInstallerService(goos string, args []string, plist string) bool {
	return resolveServiceName(args) == defaultServiceName && macInstallerServicePresent(goos, plist)
}

func (m *macInstallerService) target() string { return "system/" + macInstallerDaemonLabel }

// launchdState is what `launchctl print` says about the job: loaded or not, and
// if loaded its state ("running", "not running", "spawn scheduled", …) and pid.
// Failed is launchctl's message when it could not answer for another reason
// than the job not being loaded — then Loaded says nothing.
type launchdState struct {
	Loaded bool
	State  string
	PID    string
	Failed string
}

var (
	launchdStateRe = regexp.MustCompile(`(?m)^\s*state = (.+?)\s*$`)
	launchdPIDRe   = regexp.MustCompile(`(?m)^\s*pid = (\d+)\s*$`)
)

func (m *macInstallerService) state() launchdState {
	out, err := m.launchctl("print", m.target())
	if err != nil {
		if strings.Contains(out, "Could not find service") {
			// Not bootstrapped: installed on disk, nothing loaded in launchd.
			return launchdState{}
		}
		return launchdState{Failed: launchctlFailure(out, err)}
	}
	st := launchdState{Loaded: true}
	if mm := launchdStateRe.FindStringSubmatch(out); mm != nil {
		st.State = mm[1]
	}
	if mm := launchdPIDRe.FindStringSubmatch(out); mm != nil {
		st.PID = mm[1]
	}
	return st
}

func (m *macInstallerService) run(ctx context.Context, sub string) int {
	switch sub {
	case "status":
		return m.status(ctx)
	case "install":
		fmt.Fprintln(m.stderr, "install: the macOS installer already registered this machine's service "+
			"(launchd label "+macInstallerDaemonLabel+").")
		fmt.Fprintln(m.stderr, "  It keeps its own sign-in — open its console to sign in. To install a second,")
		fmt.Fprintln(m.stderr, "  separate client next to it, add --service-name <name>.")
		return 1
	case "uninstall":
		fmt.Fprintln(m.stderr, "uninstall: this service was installed by the macOS installer — remove it the same way:")
		fmt.Fprintln(m.stderr, "  sudo launchctl bootout "+m.target())
		fmt.Fprintln(m.stderr, "  sudo rm -f "+macInstallerDaemonPlist)
		fmt.Fprintln(m.stderr, `  sudo rm -rf "/Library/Application Support/Calabi" /Applications/Calabi.app`)
		fmt.Fprintln(m.stderr, "  (the last line also deletes the service's saved sign-in and settings)")
		return 1
	}

	// start / stop / restart act on a root job in the system domain.
	if m.euid != 0 {
		fmt.Fprintf(m.stderr, "%s: this machine's service is a root LaunchDaemon (%s) — re-run with sudo.\n",
			sub, macInstallerDaemonLabel)
		return 1
	}
	switch sub {
	case "start":
		startedAt := time.Now()
		st := m.state()
		if st.Failed != "" {
			fmt.Fprintln(m.stderr, "start:", st.Failed)
			return 1
		}
		if st.Loaded {
			// Loaded but perhaps not running (e.g. it crashed and launchd is
			// throttling the respawn): kickstart without -k starts it if needed
			// and leaves a running one alone.
			if out, err := m.launchctl("kickstart", m.target()); err != nil {
				fmt.Fprintln(m.stderr, "start:", launchctlFailure(out, err))
				return 1
			}
		} else if code := m.bootstrap("start"); code != 0 {
			return code
		}
		fmt.Fprintln(m.stdout, "  start requested.")
		m.printConsoleHint(startedAt)
		return 0
	case "stop":
		st := m.state()
		if st.Failed != "" {
			fmt.Fprintln(m.stderr, "stop:", st.Failed)
			return 1
		}
		if !st.Loaded {
			fmt.Fprintln(m.stdout, "  already stopped.")
			return 0
		}
		// bootout, not a disable: like `calabi daemon stop` everywhere else, the
		// service still comes back at the next boot.
		if out, err := m.launchctl("bootout", m.target()); err != nil {
			fmt.Fprintln(m.stderr, "stop:", launchctlFailure(out, err))
			return 1
		}
		fmt.Fprintln(m.stdout, "  stop requested.")
		return 0
	case "restart":
		startedAt := time.Now()
		st := m.state()
		if st.Failed != "" {
			fmt.Fprintln(m.stderr, "restart:", st.Failed)
			return 1
		}
		if st.Loaded {
			if out, err := m.launchctl("kickstart", "-k", m.target()); err != nil {
				fmt.Fprintln(m.stderr, "restart:", launchctlFailure(out, err))
				return 1
			}
		} else if code := m.bootstrap("restart"); code != 0 {
			return code
		}
		fmt.Fprintln(m.stdout, "  restart requested.")
		m.printConsoleHint(startedAt)
		return 0
	}
	fmt.Fprintf(m.stderr, "calabi daemon: unknown subcommand %q\n", sub)
	return 2
}

// bootstrap loads the job from its plist, the way postinstall does: enable
// first, because a service someone disabled refuses to bootstrap.
func (m *macInstallerService) bootstrap(verb string) int {
	_, _ = m.launchctl("enable", m.target())
	if out, err := m.launchctl("bootstrap", "system", macInstallerDaemonPlist); err != nil {
		fmt.Fprintln(m.stderr, verb+":", launchctlFailure(out, err))
		return 1
	}
	return 0
}

func (m *macInstallerService) status(ctx context.Context) int {
	st := m.state()
	switch {
	case st.Failed != "":
		fmt.Fprintln(m.stdout, "  installed by the macOS installer — launchctl could not report its state: "+st.Failed)
		reportServiceConsole(ctx, m.stdout, m.consoleURL(time.Time{}, 0), m.candidates)
		return 0
	case !st.Loaded:
		fmt.Fprintln(m.stdout, "  stopped (installed by the macOS installer, not loaded — start with: sudo calabi daemon start)")
		return 0
	case st.State == "running":
		if st.PID != "" {
			fmt.Fprintf(m.stdout, "  running (pid %s)\n", st.PID)
		} else {
			fmt.Fprintln(m.stdout, "  running")
		}
		reportServiceConsole(ctx, m.stdout, m.consoleURL(time.Time{}, 0), m.candidates)
		return 0
	case st.State == "":
		fmt.Fprintln(m.stdout, "  unknown (launchd has the job loaded but did not report its state)")
		return 0
	default:
		fmt.Fprintf(m.stdout, "  not running (launchd state: %s)\n", st.State)
		return 0
	}
}

func (m *macInstallerService) printConsoleHint(since time.Time) {
	if url := m.consoleURL(since, 5*time.Second); url != "" {
		fmt.Fprintln(m.stdout, "  console: "+url)
		return
	}
	fmt.Fprintln(m.stdout, `  console: starting — the address will appear in "/Library/Application Support/Calabi/daemon.log"`)
}

// launchctlFailure is launchctl's own words when it gave any, else the exit error.
func launchctlFailure(out string, err error) string {
	if out = strings.TrimSpace(out); out != "" {
		return out
	}
	return err.Error()
}
