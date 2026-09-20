// other_clients.go — noticing a calabi client this shell's data dir knows nothing
// about.
//
// Everything the account commands know comes from ONE data dir, the per-user
// one. That was enough while the daemon was something `calabi login` started.
// It is not the common case any more: the desktop installers register a
// machine-wide service whose data lives in ProgramData (Windows), /Library
// (macOS) or /var/lib/calabi (Linux) — a directory a normal shell cannot even
// list — and an org's agent is installed the same way. So a shell on such a
// machine sees "no daemon" and reports on the part of the machine it can see.
//
// The one thing every such client does expose to a non-admin shell is its local
// console, and GET /v1/service-mode is an open read that says what it runs on.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/creds"
)

// otherConsoleCandidates lists where another client's console may be answering:
// what a service next to this executable or in the machine-wide data dir last
// published (either file may be unreadable, which just drops it), and the
// default port, which is where the first client on a machine — the installed
// service — lands.
func otherConsoleCandidates() []string {
	var out []string
	seen := map[string]bool{}
	add := func(addr string) {
		if addr != "" && !seen[addr] {
			seen[addr] = true
			out = append(out, addr)
		}
	}
	if dir := exeDir(); dir != "" {
		add(consoleAddrOf(readConsoleURLFile(filepath.Join(dir, consoleURLFile)), ""))
	}
	add(consoleAddrOf(readConsoleURLFile(filepath.Join(creds.SystemDataDir(), consoleURLFile)), ""))
	add(defaultStatusAddr)
	return out
}

// otherClient is a console that answered /v1/service-mode.
type otherClient struct {
	Addr  string
	Agent bool
}

// probeOtherClients returns the candidates that are calabi consoles, skipping
// `own` — this data dir's daemon, which the caller has already dealt with.
// Anything that does not answer /v1/service-mode with a mode is not counted: an
// unrelated process on the port, or a daemon too old to say.
func probeOtherClients(ctx context.Context, own string, candidates []string) []otherClient {
	var out []otherClient
	for _, addr := range candidates {
		if addr == own {
			continue
		}
		if agent, ok := probeServiceMode(ctx, addr); ok {
			out = append(out, otherClient{Addr: addr, Agent: agent})
		}
	}
	return out
}

func probeServiceMode(ctx context.Context, addr string) (agent, ok bool) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/v1/service-mode", nil)
	if err != nil {
		return false, false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, false
	}
	var m struct {
		Mode  string `json:"mode"`
		Agent bool   `json:"agent"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&m) != nil || strings.TrimSpace(m.Mode) == "" {
		return false, false
	}
	return m.Agent, true
}

// noteOtherClients tells a logout which clients on this machine it did not
// touch, and what each one runs on — so "logged out" is never read as "this
// machine is signed out" while the desktop app's service is still signed in.
func noteOtherClients(ctx context.Context, w io.Writer, own string, candidates []string) {
	for _, c := range probeOtherClients(ctx, own, candidates) {
		if c.Agent {
			fmt.Fprintf(w, "  note: another calabi client on this machine (http://%s) runs on its own\n", c.Addr)
			fmt.Fprintln(w, "  API key — this command did not affect it")
		} else {
			fmt.Fprintf(w, "  note: another calabi client on this machine (http://%s) keeps its own\n", c.Addr)
			fmt.Fprintln(w, "  sign-in — this command did not sign it out; open its console to do that")
		}
	}
}
