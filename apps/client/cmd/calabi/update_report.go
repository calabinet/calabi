// update_report.go — delivers self-update results (U5a) to bff-console over the
// daemon's own authenticated channel, the same credential and base URL the
// upstream-health reporter uses. Platform daemon only: the standalone daemon
// never builds an update agent, so nothing here can run there. (U5a) for what is reported and why.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/calabi/calabi/apps/client/internal/creds"
	"github.com/calabi/calabi/apps/client/internal/selfupdate"
)

// newUpdateReporter returns the agent's Report function, or nil when there is no
// control plane to report to.
func newUpdateReporter(bffConsoleURL string) func(context.Context, []selfupdate.UpdateEvent) error {
	base := strings.TrimRight(strings.TrimSpace(bffConsoleURL), "/")
	if base == "" {
		return nil
	}
	httpc := &http.Client{Timeout: 10 * time.Second}
	return func(ctx context.Context, events []selfupdate.UpdateEvent) error {
		return postUpdateEvents(ctx, httpc, base, resolveReportToken(), events)
	}
}

// newOrgPolicyFetcher returns the agent's OrgPolicy source (U5c), or nil when
// there is no control plane to ask.
func newOrgPolicyFetcher(bffConsoleURL string) func(context.Context) (*selfupdate.OrgPolicy, error) {
	base := strings.TrimRight(strings.TrimSpace(bffConsoleURL), "/")
	if base == "" {
		return nil
	}
	httpc := &http.Client{Timeout: 10 * time.Second}
	return func(ctx context.Context) (*selfupdate.OrgPolicy, error) {
		return fetchOrgPolicy(ctx, httpc, base, resolveReportToken())
	}
}

func fetchOrgPolicy(ctx context.Context, httpc *http.Client, base, token string) (*selfupdate.OrgPolicy, error) {
	// No credential = this machine is in no org, so no org's rules apply.
	if token == "" {
		return nil, selfupdate.ErrNoOrg
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/org/client-update-policy", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// 401 may be an access token mid-refresh, 404 a control plane that
		// predates this endpoint: neither says the org dropped its rules, so
		// the caller keeps what it had.
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var body struct {
		OrgID        int64  `json:"org_id"`
		MinMode      string `json:"min_mode"`
		MaxDeferDays *int   `json:"max_defer_days"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body); err != nil {
		return nil, err
	}
	return &selfupdate.OrgPolicy{OrgID: body.OrgID, MinMode: body.MinMode, MaxDeferDays: body.MaxDeferDays}, nil
}

func postUpdateEvents(ctx context.Context, httpc *http.Client, base, token string, events []selfupdate.UpdateEvent) error {
	// The server finds the device the way registration does: the caller's
	// principal plus this install's fingerprint. No fingerprint means this
	// machine was never registered, so there is no device to attach results to
	// yet — keep them until there is.
	c, _ := creds.Load()
	if token == "" || c == nil || c.Fingerprint == "" {
		return selfupdate.ErrReportNoCredential
	}
	body, err := json.Marshal(map[string]any{"fingerprint": c.Fingerprint, "events": events})
	if err != nil {
		return fmt.Errorf("%w: %v", selfupdate.ErrReportRejected, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/clients/update-events", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode/100 == 2:
		return nil
	case resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusRequestEntityTooLarge:
		// Malformed as far as the server is concerned: the same bytes will be
		// refused the same way next time.
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%w: HTTP %d: %s", selfupdate.ErrReportRejected, resp.StatusCode, strings.TrimSpace(string(msg)))
	default:
		// 401/403 can be fixed by a login; 404/501 is a control plane that does
		// not have the endpoint yet; 5xx is transient. All worth keeping.
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
}
