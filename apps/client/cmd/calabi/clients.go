// CLI device management — `calabi clients <subcommand>`.
//
// rewrite: drops the direct identity-svc gRPC dial in favour of
// bff-console REST. Same surface to the user; `clients.go` is now just
// a thin shell over /v1/clients endpoints.
package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/calabi/calabi/apps/client/internal/creds"
	"github.com/calabi/calabi/apps/client/internal/platform/clientreg"
)

// runClients dispatches `calabi clients <subcommand>`.
func runClients(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "calabi clients: missing subcommand (list|register)")
		return 2
	}
	switch args[0] {
	case "list":
		return runClientsList(args[1:])
	case "register":
		return runClientsRegister(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "calabi clients: unknown subcommand %q\n", args[0])
		return 2
	}
}

// runClientsRegister explicitly registers this device. The daemon does
// this automatically post-login (see clientreg.Ensure invoked from
// daemon.go), so this command is mostly for ops / debug.
func runClientsRegister(args []string) int {
	fs := newFlagSet("clients register")
	_ = fs.String("name", "", "device label (kept for compat; hostname is always used now)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := creds.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi clients register:", err)
		return 1
	}
	if cfg == nil || cfg.User.ID == 0 {
		fmt.Fprintln(os.Stderr, "calabi clients register: not logged in (run `calabi login` first)")
		return 1
	}
	if err := clientreg.Ensure(cfg, bffURL(), version); err != nil {
		fmt.Fprintln(os.Stderr, "calabi clients register:", err)
		return 1
	}
	fmt.Printf("  registered client id=%d on host=%s os=%s/%s\n",
		cfg.DeviceID, hostnameOr("?"), runtime.GOOS, runtime.GOARCH)
	return 0
}

func runClientsList(args []string) int {
	fs := newFlagSet("clients list")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cli, err := authedClient()
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi clients list:", err)
		return 1
	}
	type clientItem struct {
		ID            int64  `json:"id"`
		Fingerprint   string `json:"fingerprint"`
		DisplayName   string `json:"display_name"`
		OsInfo        string `json:"os_info"`
		ClientVersion string `json:"client_version"`
		LastSeenAt    string `json:"last_seen_at"`
		Online        bool   `json:"online"`
		TunnelCount   int    `json:"tunnel_count"`
	}
	type resp struct {
		Items []clientItem `json:"items"`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var out resp
	if err := cli.Do(ctx, "GET", "/v1/clients", nil, &out); err != nil {
		fmt.Fprintln(os.Stderr, "calabi clients list:", err)
		return 1
	}
	if len(out.Items) == 0 {
		fmt.Println("  (no clients registered yet; run `calabi clients register`)")
		return 0
	}
	fmt.Printf("%-6s %-22s %-20s %-18s %s\n", "id", "fingerprint", "name", "os", "last_seen")
	for _, c := range out.Items {
		seen := c.LastSeenAt
		// last_seen_at is an ISO-8601 timestamp; convert to "5m" / "2h"
		// when parseable.
		if t, err := time.Parse(time.RFC3339, c.LastSeenAt); err == nil {
			seen = humanizeSince(time.Since(t))
		}
		fmt.Printf("%-6d %-22s %-20s %-18s %s\n",
			c.ID, truncate(c.Fingerprint, 22),
			truncate(c.DisplayName, 20), truncate(c.OsInfo, 18), seen)
	}
	return 0
}

// humanizeSince prints a coarse duration like "2m" / "3h" / "5d".
func humanizeSince(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "now"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// hostnameOr returns the OS hostname or a fallback when unavailable.
func hostnameOr(fallback string) string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return fallback
}
