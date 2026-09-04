// `calabi org` subcommand surface.
//
// Subcommands:
//
//	calabi org list                     show all Orgs the caller belongs to
//	calabi org current                  show the active Org (from JWT / creds)
//	calabi org switch <org-id|name>     SwitchActiveOrg + persist new tokens
//
// rewrite: drops direct identity-svc + tenant-svc gRPC dials. All
// three subcommands now go through bff-console's /v1/orgs REST surface
// so the CLI only needs CALABI_BFF_CONSOLE configured.

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/calabi/calabi/apps/client/internal/creds"
)

func runOrg(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: calabi org [list|current|switch]")
		return 2
	}
	switch args[0] {
	case "list":
		return runOrgList(args[1:])
	case "current":
		return runOrgCurrent(args[1:])
	case "switch":
		return runOrgSwitch(args[1:])
	default:
		fmt.Fprintln(os.Stderr, "calabi org: unknown subcommand", args[0])
		return 2
	}
}

// orgRow is what list / switch use internally to render + match.
type orgRow struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	State string `json:"status"`
}

func loadCredsOrDie() *creds.Config {
	c, _ := creds.Load()
	if c == nil || c.User.ID == 0 {
		fmt.Fprintln(os.Stderr, "calabi: not logged in — run `calabi login` first")
		os.Exit(2)
	}
	return c
}

// runOrgList — `calabi org list`.
func runOrgList(args []string) int {
	fs := newFlagSet("org list")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c := loadCredsOrDie()
	rows, err := listOrgsForUser()
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi org list:", err)
		return 1
	}
	if len(rows) == 0 {
		fmt.Println("  (no orgs)")
		return 0
	}
	active := c.ActiveOrgID
	fmt.Printf("%-3s %-8s %-10s %-30s %s\n", "*", "id", "kind", "name", "status")
	for _, r := range rows {
		marker := " "
		if r.ID == active {
			marker = "*"
		}
		display := r.Name
		if r.Kind == "personal" {
			display = "(Personal)"
		}
		fmt.Printf("%-3s %-8d %-10s %-30s %s\n", marker, r.ID, r.Kind, display, r.State)
	}
	return 0
}

// runOrgCurrent — `calabi org current`.
func runOrgCurrent(args []string) int {
	fs := newFlagSet("org current")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c := loadCredsOrDie()
	if c.ActiveOrgID == 0 {
		fmt.Println("  (active Org unknown — run `calabi login` to refresh, or `calabi org list`)")
		return 0
	}
	o, err := getOrg(c.ActiveOrgID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi org current:", err)
		return 1
	}
	display := o.Name
	if o.Kind == "personal" {
		display = "(Personal)"
	}
	fmt.Printf("  active org: id=%d kind=%s name=%s status=%s\n",
		o.ID, o.Kind, display, o.State)
	return 0
}

// runOrgSwitch — `calabi org switch <id-or-name>`.
//
// POST /v1/orgs/switch returns a fresh JWT pair anchored to the new Org;
// we persist the new tokens so subsequent CLI commands carry the new
// org_id claim.
func runOrgSwitch(args []string) int {
	fs := newFlagSet("org switch")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	target := fs.Arg(0)
	if target == "" {
		fmt.Fprintln(os.Stderr, "usage: calabi org switch <org-id|name>")
		return 2
	}
	c := loadCredsOrDie()
	rows, err := listOrgsForUser()
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi org switch:", err)
		return 1
	}
	var targetID int64
	if n, perr := strconv.ParseInt(target, 10, 64); perr == nil {
		for _, r := range rows {
			if r.ID == n {
				targetID = n
				break
			}
		}
	}
	if targetID == 0 {
		for _, r := range rows {
			if r.Name == target || r.Kind == target ||
				(r.Kind == "personal" && (target == "personal" || target == "个人空间")) {
				targetID = r.ID
				break
			}
		}
	}
	if targetID == 0 {
		fmt.Fprintf(os.Stderr, "calabi org switch: no Org matched %q (run `calabi org list` to inspect)\n", target)
		return 1
	}
	if targetID == c.ActiveOrgID {
		fmt.Println("  already active.")
		return 0
	}

	cli, err := authedClient()
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi:", err)
		return 1
	}
	// bff-console expects {"target_org_id": N} and decodes strictly
	// (DisallowUnknownFields), so the json tag MUST be target_org_id — a
	// plain "org_id" gets rejected with HTTP 400 "unknown field". Matches
	// POST /v1/orgs/switch in apps/bff-console/internal/handlers/orgs.go.
	type switchReq struct {
		OrgID int64 `json:"target_org_id"`
	}
	type switchResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ActiveOrgID  int64  `json:"active_org_id"`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var out switchResp
	if err := cli.Do(ctx, "POST", "/v1/orgs/switch", switchReq{OrgID: targetID}, &out); err != nil {
		fmt.Fprintln(os.Stderr, "calabi org switch:", err)
		return 1
	}
	c.AccessToken = out.AccessToken
	c.RefreshToken = out.RefreshToken
	if out.ActiveOrgID != 0 {
		c.ActiveOrgID = out.ActiveOrgID
	} else {
		// bff-console may not echo the new org_id; fall back to parsing
		// the freshly minted JWT.
		if oid := orgFromJWT(c.AccessToken); oid != 0 {
			c.ActiveOrgID = oid
		} else {
			c.ActiveOrgID = targetID
		}
	}
	if err := creds.Save(c); err != nil {
		fmt.Fprintln(os.Stderr, "calabi: save creds:", err)
		return 1
	}
	fmt.Printf("  switched to org id=%d\n", c.ActiveOrgID)
	return 0
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// listOrgsForUser pulls /v1/orgs from bff-console. The principal scope
// comes from the JWT — no user_id in the URL.
func listOrgsForUser() ([]orgRow, error) {
	cli, err := authedClient()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var resp struct {
		Items []orgRow `json:"items"`
	}
	if err := cli.Do(ctx, "GET", "/v1/orgs", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Items, nil
}

// getOrg fetches a single Org by id.
func getOrg(orgID int64) (orgRow, error) {
	cli, err := authedClient()
	if err != nil {
		return orgRow{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var o orgRow
	if err := cli.Do(ctx, "GET", fmt.Sprintf("/v1/orgs/%d", orgID), nil, &o); err != nil {
		return orgRow{}, err
	}
	return o, nil
}

// orgFromJWT decodes the middle (payload) segment of a JWT and returns
// the org_id claim. Best-effort — returns 0 on any parse failure.
func orgFromJWT(token string) int64 {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return 0
		}
	}
	var claims struct {
		OrgID int64 `json:"org_id"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return 0
	}
	return claims.OrgID
}
