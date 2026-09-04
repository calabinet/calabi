// CLI custom-domain management — `calabi domains <subcommand>`.
//
// rewrite: routes via bff-console REST (/v1/domains/*). The flow
// the user follows is unchanged:
//  1. calabi domains create <domain>       -> mints + prints verify_token
//  2. user publishes TXT _calabi-verify.<domain> = <verify_token>
//  3. calabi domains verify <domain>       -> server resolves
//  4. calabi domains bind-cert <domain> <cert-name>
//  5. calabi http <port> --domain <domain>
package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"time"
)

// runDomains handles `calabi domains <subcommand>`.
func runDomains(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "calabi domains: missing subcommand (create|verify|bind-cert|list|delete)")
		return 2
	}
	switch args[0] {
	case "create":
		return runDomainsCreate(args[1:])
	case "verify":
		return runDomainsVerify(args[1:])
	case "bind-cert":
		return runDomainsBindCert(args[1:])
	case "list":
		return runDomainsList(args[1:])
	case "delete":
		return runDomainsDelete(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "calabi domains: unknown subcommand %q\n", args[0])
		return 2
	}
}

// domainItem mirrors the JSON shape bff-console returns for a domain.
type domainItem struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Status      string `json:"status"`
	VerifyToken string `json:"verify_token"`
	VerifyError string `json:"verify_error"`
	VerifiedAt  string `json:"verified_at"`
	CertID      int64  `json:"cert_id"`
	CertName    string `json:"cert_name"`
	Observed    string `json:"observed_txt"`
	Verified    bool   `json:"verified"`
}

func runDomainsCreate(args []string) int {
	fs := newFlagSet("domains create")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "calabi domains create: missing <domain>")
		return 2
	}
	domain := fs.Arg(0)
	cli, err := authedClient()
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi domains create:", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var d domainItem
	if err := cli.Do(ctx, "POST", "/v1/domains", map[string]string{"name": domain}, &d); err != nil {
		fmt.Fprintln(os.Stderr, "calabi domains create:", err)
		return 1
	}
	fmt.Printf("  domain %q registered\n", d.Name)
	fmt.Printf("  status: %s\n\n", d.Status)
	fmt.Println("  To prove ownership, publish a DNS TXT record:")
	fmt.Printf("    Host:  _calabi-verify.%s\n", d.Name)
	fmt.Printf("    Type:  TXT\n")
	fmt.Printf("    Value: %s\n\n", d.VerifyToken)
	fmt.Printf("  Then run: calabi domains verify %s\n", d.Name)
	return 0
}

func runDomainsVerify(args []string) int {
	fs := newFlagSet("domains verify")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "calabi domains verify: missing <domain>")
		return 2
	}
	domain := fs.Arg(0)
	cli, err := authedClient()
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi domains verify:", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var d domainItem
	path := fmt.Sprintf("/v1/domains/%s/verify", url.PathEscape(domain))
	if err := cli.Do(ctx, "POST", path, nil, &d); err != nil {
		fmt.Fprintln(os.Stderr, "calabi domains verify:", err)
		return 1
	}
	if !d.Verified {
		fmt.Printf("  domain %q: NOT verified\n", d.Name)
		if d.VerifyError != "" {
			fmt.Printf("  reason: %s\n", d.VerifyError)
		}
		if d.Observed != "" {
			fmt.Printf("  observed TXT: %s\n", d.Observed)
		}
		fmt.Printf("  expected TXT: %s\n", d.VerifyToken)
		fmt.Println("  hint: DNS records can take up to 600s to propagate; try again after publishing.")
		return 1
	}
	fmt.Printf("  domain %q: VERIFIED\n", d.Name)
	if d.Observed != "" {
		fmt.Printf("  observed TXT: %s\n", d.Observed)
	}
	fmt.Printf("  next: calabi domains bind-cert %s <cert-name>\n", d.Name)
	return 0
}

func runDomainsBindCert(args []string) int {
	fs := newFlagSet("domains bind-cert")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 2 {
		fmt.Fprintln(os.Stderr, "calabi domains bind-cert: missing <domain> <cert-name>")
		return 2
	}
	domain, certName := fs.Arg(0), fs.Arg(1)
	cli, err := authedClient()
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi domains bind-cert:", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var d domainItem
	path := fmt.Sprintf("/v1/domains/%s/bind-cert", url.PathEscape(domain))
	if err := cli.Do(ctx, "POST", path, map[string]string{"cert_name": certName}, &d); err != nil {
		fmt.Fprintln(os.Stderr, "calabi domains bind-cert:", err)
		return 1
	}
	fmt.Printf("  domain %q now bound to cert %q (id=%d)\n", d.Name, d.CertName, d.CertID)
	fmt.Printf("  next: calabi http <port> --domain %s\n", d.Name)
	return 0
}

func runDomainsList(args []string) int {
	fs := newFlagSet("domains list")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cli, err := authedClient()
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi domains list:", err)
		return 1
	}
	type resp struct {
		Items []domainItem `json:"items"`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var out resp
	if err := cli.Do(ctx, "GET", "/v1/domains", nil, &out); err != nil {
		fmt.Fprintln(os.Stderr, "calabi domains list:", err)
		return 1
	}
	if len(out.Items) == 0 {
		fmt.Println("  (no domains)")
		return 0
	}
	fmt.Printf("%-30s %-10s %-20s %s\n", "domain", "status", "cert", "verified_at")
	for _, d := range out.Items {
		cert := d.CertName
		if cert == "" {
			cert = "-"
		}
		fmt.Printf("%-30s %-10s %-20s %s\n",
			truncate(d.Name, 30), d.Status, truncate(cert, 20), d.VerifiedAt)
	}
	return 0
}

func runDomainsDelete(args []string) int {
	fs := newFlagSet("domains delete")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "calabi domains delete: missing <domain>")
		return 2
	}
	domain := fs.Arg(0)
	cli, err := authedClient()
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi domains delete:", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	path := fmt.Sprintf("/v1/domains/%s", url.PathEscape(domain))
	if err := cli.Do(ctx, "DELETE", path, nil, nil); err != nil {
		fmt.Fprintln(os.Stderr, "calabi domains delete:", err)
		return 1
	}
	fmt.Printf("  domain %q deleted\n", domain)
	return 0
}
