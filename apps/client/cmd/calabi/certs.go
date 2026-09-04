// CLI cert management — `calabi certs <subcommand>`.
//
// rewrite: routes via bff-console REST (/v1/certs/upload, list,
// delete) instead of direct cert-svc gRPC. Pre-flight PEM validation
// (parse leaf cert, key/cert pair check) still happens locally so users
// get the typo error before bothering the server.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// runCerts handles `calabi certs <subcommand>`.
func runCerts(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "calabi certs: missing subcommand (upload|list|delete)")
		return 2
	}
	switch args[0] {
	case "upload":
		return runCertsUpload(args[1:])
	case "list":
		return runCertsList(args[1:])
	case "delete":
		return runCertsDelete(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "calabi certs: unknown subcommand %q\n", args[0])
		return 2
	}
}

func runCertsUpload(args []string) int {
	fs := newFlagSet("certs upload")
	name := fs.String("name", "", "label for the cert (empty = derive from leaf CN)")
	fullchainPath := fs.String("fullchain", "", "path to fullchain PEM (leaf + intermediates)")
	keyPath := fs.String("key", "", "path to private key PEM")
	if err := fs.Parse(reorderArgs(args, []string{"name", "fullchain", "key"})); err != nil {
		return 2
	}
	if *fullchainPath == "" || *keyPath == "" {
		fmt.Fprintln(os.Stderr, "calabi certs upload: --fullchain and --key are required")
		return 2
	}
	fullchain, err := os.ReadFile(*fullchainPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read fullchain:", err)
		return 1
	}
	key, err := os.ReadFile(*keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read key:", err)
		return 1
	}
	leaf, err := localValidate(fullchain, key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi certs upload:", err)
		return 1
	}
	fmt.Printf("  pre-flight: subject=%q SANs=%v not_after=%s\n",
		leaf.Subject.CommonName, leaf.DNSNames, leaf.NotAfter.Format(time.RFC3339))

	cli, err := authedClient()
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi:", err)
		return 1
	}
	type uploadReq struct {
		Name          string `json:"name"`
		FullchainPEM  string `json:"fullchain_pem"`
		PrivateKeyPEM string `json:"private_key_pem"`
	}
	type certMeta struct {
		ID          int64    `json:"id"`
		Name        string   `json:"name"`
		Fingerprint string   `json:"fingerprint"`
		Sans        []string `json:"sans"`
	}
	type uploadResp struct {
		Cert     certMeta `json:"cert"`
		Replaced bool     `json:"replaced"`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var out uploadResp
	if err := cli.Do(ctx, "POST", "/v1/certs/upload", uploadReq{
		Name:          *name,
		FullchainPEM:  string(fullchain),
		PrivateKeyPEM: string(key),
	}, &out); err != nil {
		fmt.Fprintln(os.Stderr, "calabi certs upload:", err)
		return 1
	}
	verb := "uploaded"
	if out.Replaced {
		verb = "replaced"
	}
	fmt.Printf("\n  cert %s: id=%d name=%q fingerprint=%s\n  SANs: %s\n\n",
		verb, out.Cert.ID, out.Cert.Name, out.Cert.Fingerprint,
		strings.Join(out.Cert.Sans, ", "),
	)
	return 0
}

func runCertsList(args []string) int {
	fs := newFlagSet("certs list")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cli, err := authedClient()
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi:", err)
		return 1
	}
	type certItem struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		Subject  string `json:"subject"`
		NotAfter string `json:"not_after"`
	}
	type resp struct {
		Items []certItem `json:"items"`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var out resp
	if err := cli.Do(ctx, "GET", "/v1/certs", nil, &out); err != nil {
		fmt.Fprintln(os.Stderr, "calabi certs list:", err)
		return 1
	}
	if len(out.Items) == 0 {
		fmt.Println("  (no certs)")
		return 0
	}
	fmt.Printf("%-6s %-20s %-30s %s\n", "id", "name", "subject", "not_after")
	for _, c := range out.Items {
		fmt.Printf("%-6d %-20s %-30s %s\n",
			c.ID, c.Name, truncate(c.Subject, 30), c.NotAfter)
	}
	return 0
}

func runCertsDelete(args []string) int {
	fs := newFlagSet("certs delete")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "calabi certs delete: missing <id>")
		return 2
	}
	id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi certs delete: invalid <id>:", fs.Arg(0))
		return 2
	}
	cli, err := authedClient()
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi:", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := cli.Do(ctx, "DELETE", fmt.Sprintf("/v1/certs/%d", id), nil, nil); err != nil {
		fmt.Fprintln(os.Stderr, "calabi certs delete:", err)
		return 1
	}
	fmt.Printf("  cert %d deleted\n", id)
	return 0
}

// localValidate parses the PEM pair and returns the leaf cert. Catches
// the common "wrong file picked / cert expired" gotchas before they hit
// the server.
func localValidate(fullchain, key []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(fullchain)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("fullchain doesn't start with a CERTIFICATE block")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse leaf: %w", err)
	}
	if time.Now().After(leaf.NotAfter) {
		return nil, fmt.Errorf("cert already expired (NotAfter=%s)", leaf.NotAfter.Format(time.RFC3339))
	}
	if _, err := tls.X509KeyPair(fullchain, key); err != nil {
		return nil, fmt.Errorf("cert/key pair: %w", err)
	}
	return leaf, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
