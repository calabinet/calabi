package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/creds"
)

// localTokenFor returns the local-token the daemon at base will actually accept.
//
// It ASKS THE DAEMON instead of reading the creds file, because the two are not
// always the same file. A daemon installed as a system service — every macOS
// install, and `daemon install --system` anywhere — runs with its own creds
// directory; a CLI started from a shell reads a different one and gets a token
// the daemon has never seen. The symptom is a flat 401 on every gated endpoint
// with the daemon plainly running and answering unauthenticated reads:
//
//	calabi mesh relaytest: the daemon refused the probe (401 Unauthorized):
//	{"error":"local-token mismatch (fetch /v1/local-token)"}
//
// That error names the fix and nothing was doing it. GET /v1/local-token is
// deliberately ungated on both daemon kinds — the loopback bind IS the trust
// boundary, and it is how the embedded SPA gets the token too — so the daemon is
// both the authority on its own token and reachable for it.
//
// The creds file stays as a fallback for a daemon too old to serve the endpoint.
func localTokenFor(base string) string {
	c := &http.Client{Timeout: 3 * time.Second}
	if resp, err := c.Get(base + "/v1/local-token"); err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			var out struct {
				Token string `json:"token"`
			}
			if json.NewDecoder(resp.Body).Decode(&out) == nil && out.Token != "" {
				return out.Token
			}
		}
	}
	tok, _ := creds.LoadLocalToken()
	return tok
}
