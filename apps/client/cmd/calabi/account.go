// Account-management subcommands: login / logout / keys.
//
// rewrite: all subcommands now talk to bff-console over HTTP REST
// rather than dialing identity-svc gRPC directly. Production-side the
// CLI then only needs a single public endpoint (CALABI_BFF_CONSOLE)
// matching the daemon's background paths (edgepicker + clientreg).
//
// `calabi register` was removed — user registration is only possible
// through the official console (web/console). The CLI cannot create
// users any more; tell the user to register at the website and then run
// `calabi login`.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/calabinet/calabi/apps/client/internal/creds"
	"github.com/calabinet/calabi/apps/client/internal/platform/bffclient"
	cruntime "github.com/calabinet/calabi/apps/client/internal/runtime"
)

// portRolledNote explains a console that did not land on the port the user
// expects, or "" when it did.
//
// The console rolls to the next free port when its own is taken, which is what
// makes several clients on one machine work — and is also the one genuinely
// surprising thing about this setup: you go to :7400 out of habit and find
// somebody else's client, or nothing. Worth a line, precisely because login is
// where a machine most often acquires its SECOND daemon (an org agent installed
// as a service, plus a human signing in).
func portRolledNote(consoleAddr, requested string) string {
	if consoleAddr == "" || consoleAddr == requested {
		return ""
	}
	return "  (" + requested + " was already taken — another client or service on this machine has it)"
}

// consoleAddrOf turns a published console URL ("http://127.0.0.1:7401") into
// the host:port the caller prints, falling back to `def` when nothing was
// published. The published value is the port the daemon ACTUALLY won, which on
// a machine running several clients is not the one that was asked for.
func consoleAddrOf(publishedURL, def string) string {
	u := strings.TrimSpace(publishedURL)
	u = strings.TrimPrefix(strings.TrimPrefix(u, "http://"), "https://")
	u = strings.TrimSuffix(u, "/")
	if u == "" {
		return def
	}
	return u
}

func newFlagSet(name string) *flag.FlagSet {
	return flag.NewFlagSet(name, flag.ContinueOnError)
}

// bffURL returns the resolved bff-console base URL (env override or
// compile-time default).
func bffURL() string {
	return envOr("CALABI_BFF_CONSOLE", defaultBFFConsole)
}

// refreshBearer exchanges the stored refresh_token for a fresh access
// token via bff-console /v1/auth/refresh, persists both back to creds,
// and returns the new access token. Returns "" when there's no refresh
// token or the exchange fails.
//
// Three paths use it as a recovery hook, all because nothing else refreshes a
// login session while no console is open (the local console's proxy only
// refreshes on proxied calls):
//   - edgepicker, on a 401: on a cold boot the stored access_token may have
//     expired while the daemon was down.
//   - the mesh, when the coordinator refuses its credential: an access token
//     lives 15 minutes and a long-lived edge session never asks for a new one,
//     so the mesh's first re-registration after that is refused.
//   - edge discovery for the one-shot tunnel commands (requireEdgeAddr), which
//     is the same edgepicker call and hits the same expired token — a login
//     from 20 minutes ago would otherwise surface as "discovery failed", which
//     is not what is wrong.
//
// The exchange itself is creds.RefreshSession, shared with the local
// console's proxy: one lock for the whole process (a refresh token is
// single-use), and a caller whose token was already replaced while it waited
// gets the replacement instead of spending the refresh token again.
//
// The ACCOUNT commands (domains / certs / clients) deliberately DON'T use it —
// they fail loud and tell the user to re-run `calabi login`.
func refreshBearer(ctx context.Context) string {
	// The credential the caller was just refused with is the one on disk now,
	// before we queue for the exchange lock.
	refused := ""
	if c, err := creds.Load(); err == nil && c != nil {
		refused = c.AccessToken
	}
	// Refresh is unauthenticated — the refresh_token lives in the body,
	// not the Authorization header.
	cli := bffclient.New(bffURL(), "")
	return creds.RefreshSession(ctx, refused, func(ctx context.Context, spent string) (string, string, error) {
		var out struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		}
		if err := cli.Do(ctx, "POST", "/v1/auth/refresh",
			map[string]string{"refresh_token": spent}, &out); err != nil {
			return "", "", err
		}
		return out.AccessToken, out.RefreshToken, nil
	})
}

// authedClient returns a bffclient.Client carrying the saved access
// token (or APIKey fallback). Caller is responsible for the case where
// no creds exist — `calabi login` for example wants the unauthenticated
// client.
func authedClient() (*bffclient.Client, error) {
	cfg, _ := creds.Load()
	if cfg == nil {
		return nil, errors.New("not logged in — run `calabi login` first")
	}
	tok := cfg.AccessToken
	if tok == "" {
		tok = cfg.APIKey
	}
	if tok == "" {
		return nil, errors.New("no access token in creds — run `calabi login`")
	}
	return bffclient.New(bffURL(), tok), nil
}

// runLogin handles `calabi login`.
//
// on successful login we auto-start the local daemon (skip with
// --no-start-daemon or CALABI_NO_START_DAEMON=1).
func runLogin(args []string) int {
	fs := newFlagSet("login")
	email := fs.String("email", "", "email (or phone)")
	password := fs.String("password", "", "password (interactive if omitted)")
	totpCode := fs.String("totp", "", "TOTP code (if account has 2FA enabled)")
	startDaemon := fs.Bool("start-daemon", true, "auto-start the local daemon after a successful login")
	noStartDaemon := fs.Bool("no-start-daemon", false, "shortcut for --start-daemon=false (CI / scripted)")
	if err := fs.Parse(reorderArgs(args, valueFlagsOf(fs))); err != nil {
		return 2
	}
	if *email == "" {
		*email = prompt("email: ")
	}
	if *password == "" {
		*password = promptSecret("password: ")
	}

	cli := bffclient.New(bffURL(), "") // unauthenticated for login
	type loginReq struct {
		Identifier string `json:"identifier"`
		Password   string `json:"password"`
		TotpCode   string `json:"totp_code,omitempty"`
	}
	type loginResp struct {
		AccessToken        string `json:"access_token"`
		RefreshToken       string `json:"refresh_token"`
		AccessExpiresInSec int64  `json:"access_expires_in_sec"`
		UserID             int64  `json:"user_id"`
		Email              string `json:"email"`
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var resp loginResp
	if err := cli.Do(ctx, "POST", "/v1/auth/login", loginReq{
		Identifier: *email, Password: *password, TotpCode: *totpCode,
	}, &resp); err != nil {
		fmt.Fprintln(os.Stderr, "calabi login:", err)
		return 1
	}

	c, _ := creds.Load()
	if c == nil {
		c = &creds.Config{}
	}
	// Who this file belonged to a moment ago. A running daemon holds its own
	// session and only re-reads creds when it next reconnects, so switching
	// ACCOUNTS is the one case where "logged in" and "the daemon is up" can be
	// true together and still mean the daemon is serving somebody else.
	prevUserID := c.User.ID
	c.AccessToken = resp.AccessToken
	c.RefreshToken = resp.RefreshToken
	c.User.ID = resp.UserID
	c.User.Email = resp.Email
	// stash the JWT's org_id claim as ActiveOrgID so
	// `calabi org current` works without a follow-up round-trip.
	if oid := orgFromJWT(c.AccessToken); oid != 0 {
		c.ActiveOrgID = oid
	}
	if c.Server == "" {
		c.Server = envOr("CALABI_SERVER", defaultServer)
	}
	if err := creds.Save(c); err != nil {
		fmt.Fprintln(os.Stderr, "calabi: save creds:", err)
		return 1
	}
	fmt.Printf("\n  logged in as %s\n  token saved to creds file (expires in %d sec)\n",
		c.User.Email, resp.AccessExpiresInSec)

	// consoleUp is set only when we have REASON to believe a dashboard is
	// answering at addr — so the closing hint can name it. Left empty, the hint
	// drops that half rather than sending the user to a URL nobody is serving.
	addr := envOr("CALABI_STATUS_ADDR", defaultStatusAddr)
	consoleUp := ""
	dataDir, _ := creds.DataDir()

	// "Is MY daemon running", not "is :7400 busy". One machine may run several
	// clients — separate data dirs, and the console rolls to the next free port
	// — so a port probe here answered for whichever client got there first: a
	// second instance's login saw someone else's daemon, reported success, and
	// never started the one the user actually wanted. The data-dir flock is
	// scoped exactly the way instances are.
	daemonUp := cruntime.DaemonRunning()
	dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dcancel()
	if daemonUp {
		consoleUp = liveConsoleAddr(dctx, dataDir)
	}
	switch {
	case daemonUp && consoleUp == "":
		// The lock says a daemon of this client is alive, but nothing answers
		// where it last said its console was. Say exactly that instead of
		// naming a port and then failing against it.
		fmt.Println("  a daemon of this client is running, but its console is not answering —")
		fmt.Println("  this login cannot be handed to it; restart it (`calabi daemon restart`,")
		fmt.Println("  or stop and start it) to pick up this account")
	case daemonUp:
		fmt.Println("  your daemon is already running at http://" + consoleUp)
		// It holds its own session and only re-reads creds when it next
		// reconnects, so hand this login over — but only when that changes
		// something (needsRebind: a restart costs every tunnel on it a
		// reconnect).
		//
		// Deliberately NOT gated on --no-start-daemon. That flag says "do not
		// START one" (CI, scripts); it does not say "leave the daemon that IS
		// running serving the previous account", and reading it that way puts
		// the bug straight back.
		//
		if needsRebind(prevUserID, resp.UserID, daemonConnected(dctx, consoleUp)) {
			if rerr := rebindDaemon(dctx, consoleUp); rerr != nil {
				fmt.Fprintln(os.Stderr, "  (could not hand this login to the daemon:", rerr, ")")
				fmt.Println("  note: it keeps its current session until it reconnects — restart it to switch now")
			} else {
				fmt.Println("  handed this login to it — re-dialling the edge and re-joining the meshnet")
			}
		}
	}

	// Starting one is a separate question, and only arises when none is up.
	wantStart := !daemonUp && *startDaemon && !*noStartDaemon && envOr("CALABI_NO_START_DAEMON", "") != "1"
	// An installed service is a client of its own: it keeps its own sign-in, or
	// runs on an API key, and this login does not reach it — its data dir is
	// machine-wide and this shell cannot even read it. So never start a second
	// daemon next to it (a second device for the same machine, joining the
	// meshnet as this account), and say what this login does apply to.
	//
	// serviceStatus has to answer "installed" even when this shell may not ask:
	// Windows refuses a non-admin status query outright, and that used to read as
	// "not installed" and start the second daemon on every desktop install. The
	// console answering on this machine is what says what the service runs on.
	//
	// Only a service under the DEFAULT name (or CALABI_SERVICE_NAME), or the
	// macOS installer's LaunchDaemon, is recognised. One installed with
	// --service-name is not, and login starts a daemon of its own next to it; so
	// does a console answering with no service installed at all, which is another
	// client's data dir on this machine — the multi-client setup, unchanged.
	if !daemonUp {
		if st, installed := serviceStatus(); installed {
			others := probeOtherClients(dctx, "", otherConsoleCandidates())
			fmt.Println(installedServiceNote(st, others, wantStart))
			wantStart = false
		}
	}
	if wantStart {
		since := time.Now()
		if err := spawnDetachedDaemon(); err != nil {
			fmt.Fprintln(os.Stderr, "  (could not auto-start daemon:", err, ")")
			fmt.Fprintln(os.Stderr, "  start manually with:  calabi daemon")
		} else {
			// Wait on what the NEW daemon published, not on the port: if another
			// client holds :7400 the probe answers instantly and truthfully,
			// about the wrong process. A published URL is whichever port ours
			// actually won.
			if u := awaitConsoleURLIn(dataDir, since, 5*time.Second); u != "" {
				consoleUp = consoleAddrOf(u, addr)
				fmt.Println("  daemon online at http://" + consoleUp)
			} else {
				readyCtx, cancelReady := context.WithTimeout(context.Background(), 3*time.Second)
				werr := waitForDaemonReady(readyCtx, addr, 3*time.Second)
				cancelReady()
				if werr != nil {
					fmt.Println("  daemon spawned but not yet ready — run `calabi daemon status` in a moment")
				} else {
					consoleUp = addr
					fmt.Println("  daemon online at http://" + addr)
				}
			}
		}
	}
	if n := portRolledNote(consoleUp, addr); n != "" {
		fmt.Println(n)
	}
	// NOT `calabi ui`: that command was removed (main.go exits 2 with a note
	// telling you to open the URL instead), and this line was the last thing in
	// the binary still advertising it — the closing line of a successful login
	// told you to run something that refuses to run.
	if consoleUp != "" {
		fmt.Println("  next: open http://" + consoleUp + "   (or)   calabi http 8080")
	} else {
		fmt.Println("  next: calabi http 8080   (or)   calabi daemon, for the dashboard")
	}
	fmt.Println()
	return 0
}

// logoutViaDaemon asks the daemon of THIS data dir to log itself out, through
// the same endpoint the SPA's 退出登录 button uses.
//
// Why go through the daemon at all, when this process can delete the tokens
// itself: because deleting them is only a third of logging out. The daemon
// holds a LIVE edge session, and its control loop blocks on a raw socket read
// that no context cancels — so wiping the file underneath it leaves tunnels
// forwarding, presence reporting "online", the mesh enrolled and the local
// console serving cached answers, all on a session that no longer exists
// anywhere else. It only notices at its next reconnect, which may be hours
// away, or never while the link stays up.
//
// The daemon's handler does the whole job (revoke upstream, clear creds, drop
// the response cache, kill the edge session, leave the mesh), so a success here
// means the caller has nothing left to do.
func logoutViaDaemon(ctx context.Context, addr string) error {
	tok, err := creds.LoadLocalToken()
	if err != nil {
		return fmt.Errorf("read local token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+addr+"/v1/auth/logout", nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Local-Token", tok)
	resp, err := (&http.Client{Timeout: 6 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// 403 is the agent block: a pinned API-key client has no login session
		// to end, and its credential lives in the service environment rather
		// than in this creds file. See isAgentRefusal.
		return readDaemonRefusal(resp)
	}
	return nil
}

// daemonRefusal is a daemon answering a local write with anything but 200. The
// status stays separate from the text so a caller can tell the agent block
// (403) from everything else, and Msg is the daemon's own sentence rather than
// the JSON envelope it arrived in.
type daemonRefusal struct {
	Status int
	Msg    string
}

func (e *daemonRefusal) Error() string {
	return fmt.Sprintf("daemon refused (%d): %s", e.Status, e.Msg)
}

func readDaemonRefusal(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	msg := strings.TrimSpace(string(body))
	var envelope struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &envelope) == nil && envelope.Error != "" {
		msg = envelope.Error
	}
	return &daemonRefusal{Status: resp.StatusCode, Msg: msg}
}

// isAgentRefusal reports the agent block: the daemon runs on an API key, so it
// has no sign-in to end or to replace, and it stays online as that key.
func isAgentRefusal(err error) bool {
	var r *daemonRefusal
	return errors.As(err, &r) && r.Status == http.StatusForbidden
}

// rebindDaemon tells the daemon of THIS data dir that the creds file underneath
// it just changed, so it adopts the new login instead of serving the previous
// account until its session happens to drop.
//
// It deliberately does NOT post the sign-in itself through the daemon's
// /v1/auth/login: that endpoint pins the token to the user's personal org
// (prefer_personal_org — right for a login typed into the desktop window), and
// silently changing which org `calabi login` lands in would be a worse bug than
// the one this fixes. The CLI signs in the way it always has; the daemon is only
// told to re-read.
func rebindDaemon(ctx context.Context, addr string) error {
	tok, err := creds.LoadLocalToken()
	if err != nil {
		return fmt.Errorf("read local token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+addr+"/v1/auth/rebind", nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Local-Token", tok)
	resp, err := (&http.Client{Timeout: 6 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// 403 = pinned API-key agent: its credential is the service env key, not
		// this file, and a login here was never going to move it.
		// 404 = a daemon older than this endpoint.
		return readDaemonRefusal(resp)
	}
	return nil
}

// daemonConnected reports whether the daemon at addr currently has a live edge
// session. Unauthenticated (/healthz carries no authority); any failure reads as
// "not connected", which errs toward rebinding — the cheap direction.
func daemonConnected(ctx context.Context, addr string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/healthz", nil)
	if err != nil {
		return false
	}
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var probe struct {
		State     string `json:"state"`
		Connected bool   `json:"connected"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&probe); err != nil {
		return false
	}
	return probe.Connected || probe.State == "connected"
}

// liveConsoleAddr returns the console address of THIS data dir's daemon, or ""
// when nothing is answering there.
//
// console.url is a pointer left behind by a START, not a statement about now.
// Two ways it lies, and the second is why this function exists:
//
//   - nothing removes it when a daemon exits (only matters to callers that do
//     not first check the lock — this one does);
//   - a daemon whose bind took longer than the two seconds startStatusPage
//     waits never overwrote it, so a LIVE daemon can be running behind a file
//     that names the PREVIOUS run's port. publishConsoleURLLate now closes that
//     hole, but every daemon already installed still has it.
//
// Reported by a user 2026-09-15: `calabi login` announced "your daemon is
// already running at http://127.0.0.1:7402", failed to hand the session over
// because nothing was listening there, and then blamed :7400 for being taken —
// three sentences about a port number nobody was serving. An address we have
// not confirmed must not be repeated as fact.
func liveConsoleAddr(ctx context.Context, dataDir string) string {
	addr := consoleAddrOf(awaitConsoleURLIn(dataDir, time.Time{}, 0), "")
	if addr == "" || !consoleAnswers(ctx, addr) {
		return ""
	}
	return addr
}

// consoleAnswers reports whether a calabi console is serving at addr. /healthz
// carries no authority and needs none — the question is only "is this address
// real", not "whose is it"; the caller got the address from its own data dir.
func consoleAnswers(ctx context.Context, addr string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/healthz", nil)
	if err != nil {
		return false
	}
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode >= 200 && resp.StatusCode < 500
}

// needsRebind decides whether this login is worth interrupting the daemon for.
//
// Rebinding restarts the edge session, and every tunnel on it reconnects. Doing
// that for a re-login as the SAME account while the daemon is happily connected
// would charge the user an outage for nothing — the common case is a token that
// expired in a shell, not a change of identity.
//
// So: a different account always (it is serving somebody else), and the same
// account only when the daemon is not connected — which is what an expired or
// rejected credential looks like from outside, and is exactly the state the
// login just fixed.
func needsRebind(prevUserID, newUserID int64, connected bool) bool {
	if prevUserID != 0 && prevUserID != newUserID {
		return true
	}
	return !connected
}

// runLogout handles `calabi logout`. Revokes the session server-side and wipes
// the local credentials — and, when a daemon of this config is running, makes
// IT do both, so the machine actually stops acting as the account.
func runLogout(args []string) int {
	fs := newFlagSet("logout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return logout(ctx, os.Stdout, os.Stderr, cruntime.DaemonRunning(), otherConsoleCandidates())
}

// logout is runLogout with its surroundings passed in: whether a daemon holds
// this data dir's lock, and where ANOTHER client's console might be answering.
//
// Every line it prints has to be true of the machine afterwards. It used to end
// in "logged out" whatever had happened, and three common cases made that a lie
// (all reproduced 2026-09-16):
//
//   - the daemon of this data dir runs on an API key (a container, or
//     `CALABI_API_KEY=… calabi daemon`): it refuses, keeps running as the key,
//     and never "reconnects" out of it — the key is in its environment;
//   - the daemon that matters is not this data dir's at all: an installed
//     service keeps its data machine-wide (ProgramData, /var/lib/calabi), which
//     a shell cannot even read, so the CLI never saw it and said nothing;
//   - CALABI_API_KEY is set in this shell, so every later command still
//     authenticates, whatever the creds file says.
func logout(ctx context.Context, stdout, stderr io.Writer, daemonUp bool, others []string) int {
	cfg, _ := creds.Load()
	saved := cfg != nil && (cfg.AccessToken != "" || cfg.RefreshToken != "" || cfg.APIKey != "")

	// A daemon for THIS data dir owns the live session; let it do the work.
	// (DaemonRunning is the data-dir flock, not a port probe — another client
	// on this machine has its own daemon and its own logout.)
	own := ""
	agent := false
	if daemonUp {
		dataDir, _ := creds.DataDir()
		// Verified, not merely published — see liveConsoleAddr. An unchecked
		// address here would turn into "could not log out through the running
		// daemon: connection refused", which reads as a fault in the daemon
		// rather than in the file we read.
		own = liveConsoleAddr(ctx, dataDir)
		if own == "" {
			fmt.Fprintln(stderr, "  (a daemon of this client is running but its console is not answering, "+
				"so it could not be signed out)")
		} else if err := logoutViaDaemon(ctx, own); err == nil {
			fmt.Fprintln(stdout, "  logged out — the daemon dropped its edge session, so tunnels and")
			fmt.Fprintln(stdout, "  presence are offline now, and it left the meshnet")
			noteKeyInEnvironment(stdout)
			noteOtherClients(ctx, stdout, own, others)
			return 0
		} else if isAgentRefusal(err) {
			agent = true
		} else {
			fmt.Fprintln(stderr, "  (could not log out through the running daemon:", err, ")")
		}
	}

	if saved {
		if cli, err := authedClient(); err == nil {
			// Best-effort: server might 401 if token already expired, that's fine.
			_ = cli.Do(ctx, "POST", "/v1/auth/logout", nil, nil)
		}
		// Same fields the SPA's logout clears, and for the same reasons: the API
		// key is a fallback resolveCredential would pick straight back up, and
		// ActiveOrgID belongs to the session that just ended. Fingerprint /
		// DeviceID / email stay so logging back in reuses the same device row and
		// pre-fills the form.
		cfg.AccessToken = ""
		cfg.RefreshToken = ""
		cfg.APIKey = ""
		cfg.ActiveOrgID = 0
		_ = creds.Save(cfg)
		if agent {
			fmt.Fprintln(stdout, "  cleared the sign-in saved for this client")
		} else {
			fmt.Fprintln(stdout, "  logged out (local creds cleared)")
		}
	} else if !agent {
		// Nothing to clear — and no file written just to hold nothing.
		fmt.Fprintln(stdout, "  not logged in — there was no saved sign-in to clear")
	}

	if agent {
		fmt.Fprintln(stdout, "  this client's daemon runs on an API key, not a sign-in, so logging out does")
		fmt.Fprintln(stdout, "  not stop it — it stays online as that key. Stop the daemon (or its container)")
		fmt.Fprintln(stdout, "  to take it offline; to change who it runs as, start it with a different key")
		noteOtherClients(ctx, stdout, own, others)
		return 1
	}
	noteKeyInEnvironment(stdout)
	if daemonUp {
		// Say the part that is NOT true, rather than let "logged out" cover for
		// it: the daemon kept the session it already had.
		fmt.Fprintln(stdout, "  note: a daemon is still running and keeps its current session until it")
		fmt.Fprintln(stdout, "  reconnects — stop it (`calabi daemon stop`) if you want it offline now")
		// Not noteOtherClients: with this daemon's own console silent, an answer on
		// :7400 may well be this daemon, and calling it "another client" would be
		// the kind of guess this function exists to stop making.
		return 0
	}
	noteOtherClients(ctx, stdout, own, others)
	return 0
}

// noteKeyInEnvironment says so when an API key in this shell's environment will
// keep authenticating every command after the logout. resolveCredential reads
// these ahead of the creds file's key, and no command can unset them.
func noteKeyInEnvironment(w io.Writer) {
	for _, k := range []string{"CALABI_API_KEY", "CALABI_TOKEN"} {
		if strings.TrimSpace(os.Getenv(k)) != "" {
			fmt.Fprintf(w, "  note: %s is still set in this shell, and commands keep authenticating\n", k)
			fmt.Fprintln(w, "  with it — unset it to stop")
			return
		}
	}
}

func prompt(label string) string {
	fmt.Print(label)
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

func promptSecret(label string) string {
	fmt.Print(label)
	if !term.IsTerminal(int(syscall.Stdin)) {
		return prompt("")
	}
	b, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return ""
	}
	return string(b)
}
