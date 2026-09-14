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
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/calabi/calabi/apps/client/internal/creds"
	"github.com/calabi/calabi/apps/client/internal/platform/bffclient"
)

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
// Two daemon paths use it as a recovery hook, both because nothing else
// refreshes a login session while no console is open (the local console's
// proxy only refreshes on proxied calls):
//   - edgepicker, on a 401: on a cold boot the stored access_token may have
//     expired while the daemon was down.
//   - the mesh, when the coordinator refuses its credential: an access token
//     lives 15 minutes and a long-lived edge session never asks for a new one,
//     so the mesh's first re-registration after that is refused.
//
// The exchange itself is creds.RefreshSession, shared with the local
// console's proxy: one lock for the whole process (a refresh token is
// single-use), and a caller whose token was already replaced while it waited
// gets the replacement instead of spending the refresh token again.
//
// CLI one-shot commands deliberately DON'T use this — they fail loud and
// tell the user to re-run `calabi login`.
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

	wantStart := *startDaemon && !*noStartDaemon && envOr("CALABI_NO_START_DAEMON", "") != "1"
	// Once the daemon is installed as an OS service, the service is the single
	// canonical daemon — don't auto-spawn a second one that would fight it for
	// :7400 and this account's tunnel claims. Defer to the service instead.
	if wantStart && serviceInstalled() {
		fmt.Println("  daemon runs as an installed service — start it with `calabi daemon start` if it isn't already")
		wantStart = false
	}
	if wantStart {
		addr := envOr("CALABI_STATUS_ADDR", defaultStatusAddr)
		switch {
		case daemonAlreadyRunning(addr):
			fmt.Println("  daemon already running at http://" + addr)
		default:
			if err := spawnDetachedDaemon(); err != nil {
				fmt.Fprintln(os.Stderr, "  (could not auto-start daemon:", err, ")")
				fmt.Fprintln(os.Stderr, "  start manually with:  calabi daemon")
			} else {
				readyCtx, cancelReady := context.WithTimeout(context.Background(), 5*time.Second)
				if werr := waitForDaemonReady(readyCtx, addr, 5*time.Second); werr != nil {
					fmt.Println("  daemon spawned but not yet ready — open http://" + addr + " in a moment")
				} else {
					fmt.Println("  daemon online at http://" + addr)
				}
				cancelReady()
			}
		}
	}
	fmt.Println("  next: calabi ui   (or)   calabi http 8080")
	fmt.Println()
	return 0
}

// runLogout handles `calabi logout`. Revokes the refresh token server-
// side via POST /v1/auth/logout, then wipes local creds either way.
func runLogout(args []string) int {
	fs := newFlagSet("logout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cli, err := authedClient()
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// Best-effort: server might 401 if token already expired, that's fine.
		_ = cli.Do(ctx, "POST", "/v1/auth/logout", nil, nil)
	}
	// Clear local creds regardless.
	cfg, _ := creds.Load()
	if cfg != nil {
		cfg.AccessToken = ""
		cfg.RefreshToken = ""
		cfg.APIKey = ""
		_ = creds.Save(cfg)
	}
	fmt.Println("  logged out (local creds cleared)")
	return 0
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
