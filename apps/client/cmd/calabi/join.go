package main

// `calabi join <invite>`: the terminal's way onto a self-hosted server, as
// `calabi login` is onto calabi.net. Joining the coordinator is the whole sign-in — it then names the edge
// for tunnels and signs this device's way in — so once it is done,
// `calabi http 8080` works, and the daemon serves the tunnels and the mesh.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/creds"
	cruntime "github.com/calabinet/calabi/apps/client/internal/runtime"
	"github.com/calabinet/calabi/apps/client/internal/selfhosted"
)

func runJoin(args []string) int {
	fs := newFlagSet("join")
	name := fs.String("name", "", "this device's name on the server (default: the host name)")
	pin := fs.String("pin", "", "the coordinator's certificate fingerprint, for an invite that carries none (`calabi-coord fingerprint` prints it)")
	replace := fs.Bool("replace", false, "join even though this device already joined a server; it leaves that one")
	startDaemon := fs.Bool("start-daemon", true, "start the daemon after joining")
	noStartDaemon := fs.Bool("no-start-daemon", false, "shortcut for --start-daemon=false (CI / scripted)")
	if err := fs.Parse(reorderArgs(args, valueFlagsOf(fs))); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: calabi join [--name NAME] <invite>")
		fmt.Fprintln(os.Stderr, "  <invite> is the calabi://join link `calabi-coord invite` prints on the server")
		return 2
	}
	link := strings.TrimSpace(fs.Arg(0))
	inv, err := selfhosted.ParseInvite(link)
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi join:", err)
		return 2
	}
	in := joinRequest{Mesh: &joinMesh{Link: link, Pin: strings.TrimSpace(*pin), Name: *name}, Replace: *replace}

	// This client's daemon, if it runs, does the join itself — it has to start
	// again to use it anyway. Otherwise the join is written here, and a daemon
	// started on it.
	dataDir, _ := creds.DataDir()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var console string
	if cruntime.DaemonRunning() {
		console = liveConsoleAddr(ctx, dataDir)
		if console == "" {
			fmt.Fprintln(os.Stderr, "calabi join: a daemon of this client is running, but its console is not answering;")
			fmt.Fprintln(os.Stderr, "  restart it (`calabi daemon restart`, or stop and start it), then join again")
			return 1
		}
	}

	for {
		var status int
		var body map[string]any
		if console != "" {
			status, body = joinThroughDaemon(ctx, console, in)
		} else {
			status, body = joinHere(ctx, in)
		}
		if status == http.StatusOK {
			break
		}
		code, _ := body["code"].(string)
		if code == "untrusted" && in.Mesh.Pin == "" {
			if p := confirmCoordinatorPin(body); p != "" {
				in.Mesh.Pin = p
				continue
			}
		}
		fmt.Fprintln(os.Stderr, "calabi join:", explainJoinFailure(code, body))
		return 1
	}

	fmt.Println()
	if console != "" {
		fmt.Println("  joined — the daemon is starting again to use this server")
		if waitForSelfHosted(ctx, console, inv.Server) {
			fmt.Println("  daemon online at http://" + console)
		} else {
			fmt.Println("  the daemon has not come back yet — check `calabi daemon status` in a moment")
		}
	} else {
		fmt.Println("  joined")
		if !*startDaemon || *noStartDaemon || envOr("CALABI_NO_START_DAEMON", "") == "1" {
			fmt.Println("  next: calabi daemon   (tunnels in the console, and the mesh)   or   calabi http 8080")
			fmt.Println()
			return 0
		}
		if st, installed := serviceStatus(); installed {
			fmt.Println(joinServiceNote(st))
			fmt.Println()
			return 0
		}
		since := time.Now()
		if err := spawnDetachedDaemon(); err != nil {
			fmt.Fprintln(os.Stderr, "  (could not start the daemon:", err, ")")
			fmt.Fprintln(os.Stderr, "  start it with:  calabi daemon")
		} else if u := awaitConsoleURLIn(dataDir, since, 5*time.Second); u != "" {
			console = consoleAddrOf(u, envOr("CALABI_STATUS_ADDR", defaultStatusAddr))
			fmt.Println("  daemon online at http://" + console)
		} else {
			fmt.Println("  daemon started — `calabi daemon status` shows it in a moment")
		}
	}
	if console != "" {
		fmt.Println("  next: open http://" + console + "   (or)   calabi http 8080")
	} else {
		fmt.Println("  next: calabi http 8080")
	}
	fmt.Println()
	return 0
}

// joinThroughDaemon asks this client's running daemon to join: POST
// /v1/selfhosted/join, as the console does.
func joinThroughDaemon(ctx context.Context, console string, in joinRequest) (int, map[string]any) {
	base := "http://" + console
	b, _ := json.Marshal(in)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/selfhosted/join", bytes.NewReader(b))
	if err != nil {
		return 0, map[string]any{"error": err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Local-Token", localTokenFor(base))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, map[string]any{"error": err.Error()}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var body map[string]any
	if json.Unmarshal(raw, &body) != nil {
		body = map[string]any{"error": fmt.Sprintf("the daemon answered %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))}
	}
	if resp.StatusCode == http.StatusNotFound {
		// Name WHICH daemon: on a machine that already runs calabi, it is that
		// client — often not the copy of calabi this command was run from.
		body = map[string]any{"error": "the calabi daemon already running for this user (console " + base + ") " +
			"is too old to join a self-hosted server.\n  Update it (`calabi update`), or stop it, then join again."}
	}
	return resp.StatusCode, body
}

// joinHere joins with no daemon running: the join is written to this client's
// data directory, and the mode set to standalone.
func joinHere(ctx context.Context, in joinRequest) (int, map[string]any) {
	if m := strings.TrimSpace(os.Getenv("CALABI_MODE")); m != "" && !strings.EqualFold(m, clientModeStandalone) {
		return http.StatusForbidden, map[string]any{"code": "mode_forced"}
	}
	if c, _ := creds.Load(); c != nil && (c.AccessToken != "" || c.RefreshToken != "" || c.APIKey != "") {
		return http.StatusConflict, map[string]any{"code": "signed_in", "email": c.User.Email}
	}
	path := managedConfigPath()
	cur, _, err := loadLocalConfigOrEmpty(path, true)
	if err != nil {
		fmt.Fprintln(os.Stderr, "  (the saved tunnels.yaml is unreadable; starting over:", err, ")")
		cur = &localConfig{}
	}
	// Read before joining: a new coordinator's record replaces it.
	oldRec := loadMeshReauth(cur.Mesh.Coord)
	next, fail := joinSelfHosted(ctx, *cur, in)
	if fail != nil {
		return fail.status, fail.body
	}
	if cur.Mesh.Coord != "" && cur.Mesh.Coord != next.Mesh.Coord {
		sctx, scancel := context.WithTimeout(ctx, 8*time.Second)
		if err := coordSignOut(sctx, cur.Mesh, oldRec); err != nil {
			fmt.Fprintln(os.Stderr, "  (could not tell the previous server this device left:", err, ")")
		}
		scancel()
	}
	if err := writeLocalConfig(path, next); err != nil {
		return http.StatusInternalServerError, map[string]any{"error": "save: " + err.Error()}
	}
	if err := setClientMode(clientModeStandalone); err != nil {
		return http.StatusInternalServerError, map[string]any{"error": "save the mode: " + err.Error()}
	}
	return http.StatusOK, map[string]any{"coord": next.Mesh.Coord}
}

// confirmCoordinatorPin shows the certificate the coordinator presents and asks
// whether it is the one the server prints; the pin when it is.
func confirmCoordinatorPin(body map[string]any) string {
	p, _ := body["pin"].(string)
	if p == "" {
		return ""
	}
	fmt.Println()
	fmt.Println("  The server's certificate is not one this device trusts, and the invite")
	fmt.Println("  names no fingerprint. It presents:")
	fmt.Println()
	fmt.Println("    " + p)
	if s, _ := body["subject"].(string); s != "" {
		fmt.Println("    (" + s + ")")
	}
	fmt.Println()
	fmt.Println("  Compare it with what `calabi-coord fingerprint` prints on the server.")
	if a := strings.ToLower(prompt("  Is it the same? [y/N] ")); a == "y" || a == "yes" {
		return p
	}
	return ""
}

// explainJoinFailure is a refused join, for the terminal.
func explainJoinFailure(code string, body map[string]any) string {
	msg, _ := body["error"].(string)
	switch code {
	case "signed_in":
		who, _ := body["email"].(string)
		if who != "" {
			who = " as " + who
		}
		return "this client is signed in to calabi.net" + who + "; sign out first (`calabi logout`), then join"
	case "mode_forced", "agent":
		return "this client is held on calabi.net (CALABI_MODE, or an installed API-key service); it cannot join a self-hosted server"
	case "joined":
		srv, _ := body["server"].(string)
		return "this device already joined " + srv + "; pass --replace to leave it and join this one"
	case "untrusted":
		return "the server's certificate is not one this device trusts; pass --pin with what `calabi-coord fingerprint` prints on the server"
	case "pin_mismatch":
		return "the server's certificate does not match the invite's fingerprint — this may not be your server; check the invite"
	case "key_refused":
		return "the server did not accept this invite: it may be used up, expired or revoked — ask for a new one"
	case "disabled":
		return "this device is disabled on that server"
	case "full":
		return "that server has no room for another device"
	case "no_tls":
		return "the server does not use TLS, and the invite does not say it may be plaintext"
	}
	if msg == "" {
		msg = "the join failed"
	}
	return msg
}

// waitForSelfHosted follows the daemon through its restart: true once it
// answers as the self-hosted daemon on coord.
func waitForSelfHosted(ctx context.Context, console, coord string) bool {
	time.Sleep(800 * time.Millisecond) // the old daemon is still answering for a moment
	deadline := time.Now().Add(45 * time.Second)
	c := &http.Client{Timeout: 2 * time.Second}
	for time.Now().Before(deadline) && ctx.Err() == nil {
		if resp, err := c.Get("http://" + console + "/v1/selfhosted"); err == nil {
			var st struct {
				Mode string `json:"mode"`
				Mesh struct {
					Server string `json:"server"`
				} `json:"mesh"`
			}
			_ = json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&st)
			resp.Body.Close()
			if st.Mode == "self_hosted" && st.Mesh.Server == coord {
				return true
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}
