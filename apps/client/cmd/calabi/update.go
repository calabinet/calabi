package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// `calabi update` — the notification surface for machines with no screen.
//
// Linux servers and unattended agents are the population most likely to sit six
// versions behind, and they are the one population that never opens the :7400
// console. The CLI is where they find out.
//
// It drives the RUNNING DAEMON rather than doing the work itself: the daemon
// holds the update agent, and on a system install the daemon is the privileged
// process — the only one that can actually install anything. A second
// implementation here would be a second set of signature checks to keep in step,
// which is exactly the shape of bug this package is careful about.
func runUpdate(args []string) int {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	checkOnly := fs.Bool("check", false, "only report what is available; do not install")
	jsonOut := fs.Bool("json", false, "print the raw status as JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: calabi update [--check] [--json]")
		fmt.Fprintln(os.Stderr, "\nAsks the running daemon to check for a new version, and installs it")
		fmt.Fprintln(os.Stderr, "when this machine is able to. Change what happens automatically in the")
		fmt.Fprintln(os.Stderr, "console at http://127.0.0.1:7400 → Settings.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	snap, base, err := daemonUpdateStatus(!*checkOnly)
	if err != nil {
		fmt.Fprintf(os.Stderr, "calabi update: %v\n", err)
		return 1
	}
	if *jsonOut {
		b, _ := json.MarshalIndent(snap, "", "  ")
		fmt.Println(string(b))
		return 0
	}
	printUpdateStatus(snap, base, *checkOnly)
	if snap.Error != "" {
		return 1
	}
	return 0
}

// updateSnap mirrors selfupdate.Snapshot, loosely: only what the CLI prints.
// Loose on purpose — a newer daemon may answer with fields this binary predates,
// and `calabi update` from an old client must still be able to say "1.12.0 is
// available" rather than fail to parse.
type updateSnap struct {
	Current   string `json:"current"`
	Latest    string `json:"latest"`
	Available bool   `json:"available"`
	CanApply  bool   `json:"can_apply"`
	Critical  bool   `json:"critical"`
	Mandatory bool   `json:"mandatory"`
	Reason    string `json:"reason"`
	Hold      string `json:"hold"`
	State     string `json:"state"`
	Error     string `json:"error"`
	Policy    struct {
		Mode string `json:"mode"`
	} `json:"policy"`
	OrgPolicy *struct {
		MinMode      string `json:"min_mode"`
		MaxDeferDays *int   `json:"max_defer_days"`
	} `json:"org_policy"`
}

// daemonUpdateStatus asks the local daemon to re-check, and optionally to
// install. Returns the snapshot and the console base URL it came from.
func daemonUpdateStatus(apply bool) (*updateSnap, string, error) {
	base, err := findDaemonConsole()
	if err != nil {
		return nil, "", err
	}
	tok, err := fetchLocalTokenFrom(base)
	if err != nil {
		return nil, base, err
	}
	// Always re-check first, even when installing: `calabi update` run by a
	// person means "find out now", not "act on whatever was cached six hours
	// ago".
	snap, err := postUpdate(base, "/v1/update/check", tok)
	if err != nil {
		return nil, base, err
	}
	if !apply || !snap.Available {
		return snap, base, nil
	}
	if !snap.CanApply {
		return snap, base, nil // printUpdateStatus explains why
	}
	applied, err := postUpdate(base, "/v1/update/apply", tok)
	if err != nil {
		return snap, base, err
	}
	return applied, base, nil
}

func postUpdate(base, path, token string) (*updateSnap, error) {
	req, err := http.NewRequest(http.MethodPost, base+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Local-Token", token)
	// Generous: the apply downloads an installer before it answers.
	resp, err := (&http.Client{Timeout: 10 * time.Minute}).Do(req)
	if err != nil {
		// The installer restarts the daemon, so the connection dying mid-apply is
		// the SUCCESS path on some platforms. Say so instead of reporting a
		// failure at the moment the thing worked.
		if path == "/v1/update/apply" {
			return &updateSnap{State: "updating"}, nil
		}
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("this daemon has no self-update (a dev build, or updates are disabled)")
	}
	var snap updateSnap
	if err := json.Unmarshal(body, &snap); err != nil {
		return nil, fmt.Errorf("daemon answered %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return &snap, nil
}

func fetchLocalTokenFrom(base string) (string, error) {
	resp, err := http.Get(base + "/v1/local-token")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out); err != nil || out.Token == "" {
		return "", fmt.Errorf("could not get a local token from %s (is this daemon yours?)", base)
	}
	return out.Token, nil
}

// findDaemonConsole returns the first local console that answers, reusing the
// same candidate list `calabi mesh status` walks — the daemon's recorded bound
// address first, the default port last. Assuming :7400 is wrong whenever a
// second client is running on the machine.
func findDaemonConsole() (string, error) {
	// dialMeshConsole's second return is the base that ANSWERED on success, and
	// the list it tried on failure — which is exactly what each message wants.
	resp, where, err := dialMeshConsole("/healthz")
	if err != nil {
		return "", fmt.Errorf("no daemon answering on %s — is it running?", where)
	}
	resp.Body.Close()
	return where, nil
}

func printUpdateStatus(s *updateSnap, base string, checkOnly bool) {
	fmt.Printf("current:   %s\n", orDash(s.Current))
	fmt.Printf("available: %s\n", describeAvailable(s))
	if s.Error != "" {
		fmt.Printf("error:     %s\n", s.Error)
		return
	}
	if !s.Available {
		return
	}
	switch {
	case s.State == "updating":
		fmt.Println("status:    installing now — the daemon will restart")
	case !s.CanApply:
		fmt.Printf("status:    this install cannot update itself (%s)\n", orDash(s.Reason))
		// The advice has to match the reason. "Download it by hand" is right when
		// nothing was published for this platform; for a daemon that simply is not
		// running as a service it is a chore that fixes nothing — reinstalling is
		// the actual answer, and it is one command.
		switch s.Reason {
		case "managed-elsewhere":
			// Running the platform installer here would install something
			// ELSE (a desktop app beside a scoop install, a.pkg beside a
			// Homebrew one) rather than update this binary.
			fmt.Println("           it was not installed by the Calabi installer, so it does not")
			fmt.Println("           update itself. Update it the way you installed it:")
			fmt.Println("             brew upgrade calabi   |   scoop update calabi   |   a new archive")
		case "not-privileged":
			fmt.Println("           this daemon is not running as a privileged OS service, so it")
			fmt.Println("           cannot replace itself. Reinstall it as one:")
			fmt.Println("             calabi daemon install --system")
		default:
			fmt.Println("           download the new version and install it by hand")
		}
	case checkOnly:
		fmt.Println("status:    run `calabi update` to install it")
	case s.Hold != "":
		fmt.Printf("status:    waiting (%s) — mode %q\n", s.Hold, s.Policy.Mode)
	}
	// The org's requirement explains a machine updating more eagerly than its
	// own mode says, which is otherwise a mystery from this side.
	if o := s.OrgPolicy; o != nil {
		var req []string
		if o.MinMode != "" {
			req = append(req, fmt.Sprintf("mode at least %q", o.MinMode))
		}
		if o.MaxDeferDays != nil {
			req = append(req, fmt.Sprintf("updates held back at most %d days", *o.MaxDeferDays))
		}
		if len(req) > 0 {
			fmt.Printf("org:       requires %s\n", strings.Join(req, ", "))
		}
	}
	if base != "" {
		fmt.Printf("settings:  %s → Settings\n", base)
	}
}

func describeAvailable(s *updateSnap) string {
	if !s.Available {
		if s.Latest != "" {
			return "no (this is the latest)"
		}
		return "unknown"
	}
	out := s.Latest
	switch {
	case s.Mandatory:
		out += "  (REQUIRED — this version is no longer supported)"
	case s.Critical:
		out += "  (security update)"
	}
	return out
}
