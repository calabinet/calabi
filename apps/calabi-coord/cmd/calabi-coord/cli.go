package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

// `calabi-coord authkey` and `calabi-coord invite`: mint, list and revoke the
// coordinator's own auth keys, and hand one to a device as a link and a QR code.
//
// They talk to the RUNNING coordinator through its admin API rather than to its
// database, so they work the same with a database and without one, and an
// invite's fingerprint is the one the listener actually serves. That needs the
// admin API on: CALABI_COORD_MESH_ADMIN_ADDR and _TOKEN, the same two variables
// the coordinator reads, so running these next to it with its environment is
// enough.

// adminClient calls the coordinator's admin API.
type adminClient struct {
	base  string // http://host:port
	token string
	hc    *http.Client
}

// adminFlags are the flags every subcommand shares.
type adminFlags struct {
	admin, token *string
	meshnet      *int64
}

func addAdminFlags(fs *flag.FlagSet) adminFlags {
	return adminFlags{
		admin:   fs.String("admin", env("MESH_ADMIN_ADDR"), "the coordinator's admin API (default: CALABI_COORD_MESH_ADMIN_ADDR)"),
		token:   fs.String("token", env("MESH_ADMIN_TOKEN"), "its token (default: CALABI_COORD_MESH_ADMIN_TOKEN)"),
		meshnet: fs.Int64("meshnet", 1, "the meshnet (the number the key file maps keys to)"),
	}
}

func (f adminFlags) client() (*adminClient, error) {
	if strings.TrimSpace(*f.admin) == "" || strings.TrimSpace(*f.token) == "" {
		return nil, errors.New("the coordinator's admin API is needed: set CALABI_COORD_MESH_ADMIN_ADDR and CALABI_COORD_MESH_ADMIN_TOKEN " +
			"on the coordinator (and here), or pass --admin and --token")
	}
	return &adminClient{base: adminBaseURL(*f.admin), token: strings.TrimSpace(*f.token), hc: &http.Client{Timeout: 10 * time.Second}}, nil
}

// adminBaseURL turns a listen address (":9500", "0.0.0.0:9500") into one to
// dial; a URL passes through.
func adminBaseURL(addr string) string {
	addr = strings.TrimSpace(addr)
	if strings.Contains(addr, "://") {
		return strings.TrimRight(addr, "/")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port)
}

func (c *adminClient) do(method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("the coordinator's admin API at %s: %w", c.base, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(raw)))
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

type cliAuthKey struct {
	ID          int64    `json:"id"`
	Prefix      string   `json:"prefix"`
	Tags        []string `json:"tags"`
	MaxUses     int      `json:"max_uses"`
	Uses        int      `json:"uses"`
	ExpiresAtMS int64    `json:"expires_at_ms"`
	RevokedAtMS int64    `json:"revoked_at_ms"`
	Note        string   `json:"note"`
	Key         string   `json:"key"`
}

// keyOptions are the flags that shape a new key, shared by `authkey create`
// and `invite`.
type keyOptions struct {
	uses     *int
	reusable *bool
	expires  *time.Duration
	noExpiry *bool
	tags     []string
	note     *string
}

func addKeyFlags(fs *flag.FlagSet) *keyOptions {
	o := &keyOptions{
		uses:     fs.Int("uses", 1, "how many devices it may admit"),
		reusable: fs.Bool("reusable", false, "any number of devices (instead of --uses)"),
		expires:  fs.Duration("expires", 24*time.Hour, "how long it admits new devices; devices it admitted stay"),
		noExpiry: fs.Bool("no-expiry", false, "never expires (instead of --expires)"),
		note:     fs.String("note", "", "your own label, shown in the list"),
	}
	fs.Func("tag", "an ACL tag for every device it admits, tag:<name>; repeatable", func(v string) error {
		o.tags = append(o.tags, v)
		return nil
	})
	return o
}

func (o *keyOptions) request() map[string]any {
	req := map[string]any{"tags": o.tags, "note": *o.note}
	if *o.reusable {
		req["reusable"] = true
	} else {
		req["max_uses"] = *o.uses
	}
	if *o.noExpiry {
		req["no_expiry"] = true
	} else {
		req["expires_in_seconds"] = int64(o.expires.Seconds())
	}
	return req
}

func runAuthKey(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: calabi-coord authkey create|list|revoke [flags]")
		return 2
	}
	switch args[0] {
	case "create":
		return runAuthKeyCreate(args[1:])
	case "list":
		return runAuthKeyList(args[1:])
	case "revoke":
		return runAuthKeyRevoke(args[1:])
	}
	fmt.Fprintf(os.Stderr, "calabi-coord authkey: unknown command %q (create, list, revoke)\n", args[0])
	return 2
}

func runAuthKeyCreate(args []string) int {
	fs := flag.NewFlagSet("authkey create", flag.ContinueOnError)
	af, ko := addAdminFlags(fs), addKeyFlags(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c, err := af.client()
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi-coord authkey create:", err)
		return 1
	}
	var k cliAuthKey
	if err := c.do(http.MethodPost, fmt.Sprintf("/admin/meshnets/%d/authkeys", *af.meshnet), ko.request(), &k); err != nil {
		fmt.Fprintln(os.Stderr, "calabi-coord authkey create:", err)
		return 1
	}
	fmt.Println(k.Key)
	fmt.Fprintf(os.Stderr, "\n%s. This is the only time the key is shown.\n", describeKey(k))
	return 0
}

func runAuthKeyList(args []string) int {
	fs := flag.NewFlagSet("authkey list", flag.ContinueOnError)
	af := addAdminFlags(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c, err := af.client()
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi-coord authkey list:", err)
		return 1
	}
	var out struct {
		Items []cliAuthKey `json:"items"`
	}
	if err := c.do(http.MethodGet, fmt.Sprintf("/admin/meshnets/%d/authkeys", *af.meshnet), nil, &out); err != nil {
		fmt.Fprintln(os.Stderr, "calabi-coord authkey list:", err)
		return 1
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tKEY\tUSES\tEXPIRES\tSTATE\tTAGS\tNOTE")
	now := time.Now()
	for _, k := range out.Items {
		uses := strconv.Itoa(k.Uses) + "/" + strconv.Itoa(k.MaxUses)
		if k.MaxUses == 0 {
			uses = strconv.Itoa(k.Uses) + "/any"
		}
		expires, state := "never", "usable"
		if k.ExpiresAtMS != 0 {
			at := time.UnixMilli(k.ExpiresAtMS)
			expires = at.Local().Format("2006-01-02 15:04")
			if !now.Before(at) {
				state = "expired"
			}
		}
		if k.MaxUses > 0 && k.Uses >= k.MaxUses {
			state = "used up"
		}
		if k.RevokedAtMS != 0 {
			state = "revoked"
		}
		fmt.Fprintf(tw, "%d\t%s…\t%s\t%s\t%s\t%s\t%s\n", k.ID, k.Prefix, uses, expires, state, strings.Join(k.Tags, ","), k.Note)
	}
	_ = tw.Flush()
	return 0
}

func runAuthKeyRevoke(args []string) int {
	fs := flag.NewFlagSet("authkey revoke", flag.ContinueOnError)
	af := addAdminFlags(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: calabi-coord authkey revoke [flags] <id>   (the ID column of authkey list)")
		return 2
	}
	id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi-coord authkey revoke: the id is a number from authkey list")
		return 2
	}
	c, err := af.client()
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi-coord authkey revoke:", err)
		return 1
	}
	if err := c.do(http.MethodDelete, fmt.Sprintf("/admin/meshnets/%d/authkeys/%d", *af.meshnet, id), nil, nil); err != nil {
		fmt.Fprintln(os.Stderr, "calabi-coord authkey revoke:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "Key %d revoked. Devices it already admitted stay; to remove one, disable or delete it.\n", id)
	return 0
}

// cliNode is the part of GET /admin/meshnets/{id}/nodes the device list shows.
type cliNode struct {
	ID       int64    `json:"id"`
	Name     string   `json:"name"`
	OS       string   `json:"os"`
	Overlay  string   `json:"overlay"`
	Online   bool     `json:"online"`
	Approved bool     `json:"approved"`
	Disabled bool     `json:"disabled"`
	Tags     []string `json:"tags"`
	LastSeen string   `json:"last_seen"`
}

// runDevice is `calabi-coord device`: the devices of a meshnet, and what an
// operator does to one. Disabling or deleting a device ends its mesh session at
// once; its tunnels stop when the grant it holds for the edge runs out, within
// the hour.
func runDevice(args []string) int {
	const usage = "usage: calabi-coord device list | approve <id> | disable <id> | enable <id> | delete <id>   [flags]"
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	if args[0] == "list" {
		return runDeviceList(args[1:])
	}
	path := map[string]string{
		"approve": "/admin/meshnets/%[1]d/nodes/%[2]d/approve",
		"disable": "/admin/nodes/%[2]d/disable",
		"enable":  "/admin/nodes/%[2]d/enable",
		"delete":  "/admin/meshnets/%[1]d/nodes/%[2]d",
	}[args[0]]
	if path == "" {
		fmt.Fprintf(os.Stderr, "calabi-coord device: unknown command %q\n%s\n", args[0], usage)
		return 2
	}
	fs := flag.NewFlagSet("device "+args[0], flag.ContinueOnError)
	af := addAdminFlags(fs)
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "usage: calabi-coord device %s [flags] <id>   (the ID column of device list)\n", args[0])
		return 2
	}
	id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "calabi-coord device %s: the id is a number from device list\n", args[0])
		return 2
	}
	c, err := af.client()
	if err != nil {
		fmt.Fprintf(os.Stderr, "calabi-coord device %s: %v\n", args[0], err)
		return 1
	}
	method := http.MethodPost
	if args[0] == "delete" {
		method = http.MethodDelete
	}
	if err := c.do(method, fmt.Sprintf(path, *af.meshnet, id), nil, nil); err != nil {
		fmt.Fprintf(os.Stderr, "calabi-coord device %s: %v\n", args[0], err)
		return 1
	}
	switch args[0] {
	case "approve":
		fmt.Fprintf(os.Stderr, "Device %d approved.\n", id)
	case "enable":
		fmt.Fprintf(os.Stderr, "Device %d enabled.\n", id)
	case "disable":
		fmt.Fprintf(os.Stderr, "Device %d disabled: it has left the mesh, and its tunnels stop within the hour. `device enable %d` brings it back.\n", id, id)
	case "delete":
		fmt.Fprintf(os.Stderr, "Device %d deleted: it has left the mesh, and its tunnels stop within the hour. It needs a new invite to join again.\n", id)
	}
	return 0
}

func runDeviceList(args []string) int {
	fs := flag.NewFlagSet("device list", flag.ContinueOnError)
	af := addAdminFlags(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c, err := af.client()
	if err != nil {
		fmt.Fprintln(os.Stderr, "calabi-coord device list:", err)
		return 1
	}
	var nodes []cliNode
	if err := c.do(http.MethodGet, fmt.Sprintf("/admin/meshnets/%d/nodes", *af.meshnet), nil, &nodes); err != nil {
		fmt.Fprintln(os.Stderr, "calabi-coord device list:", err)
		return 1
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tNAME\tOS\tADDRESS\tSTATE\tLAST SEEN\tTAGS")
	for _, n := range nodes {
		state := "offline"
		switch {
		case n.Disabled:
			state = "disabled"
		case !n.Approved:
			state = "waiting for approval"
		case n.Online:
			state = "online"
		}
		seen := n.LastSeen
		if t, err := time.Parse(time.RFC3339, n.LastSeen); err == nil {
			seen = t.Local().Format("2006-01-02 15:04")
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n", n.ID, n.Name, n.OS, n.Overlay, state, seen, strings.Join(n.Tags, ","))
	}
	_ = tw.Flush()
	return 0
}

// runInvite mints a key and prints it as a link, a QR code and a command line.
func runInvite(args []string) int {
	fs := flag.NewFlagSet("invite", flag.ContinueOnError)
	af, ko := addAdminFlags(fs), addKeyFlags(fs)
	server := fs.String("server", env("PUBLIC_ADDR"), "the address devices dial, host:port (default: CALABI_COORD_PUBLIC_ADDR)")
	pin := fs.Bool("pin", false, "put the certificate's fingerprint in the link even though the coordinator has a configured certificate")
	noPin := fs.Bool("no-pin", false, "leave the fingerprint out even for a self-signed certificate (devices then need to trust it some other way)")
	allowPlaintext := fs.Bool("allow-plaintext", false, "invite to a coordinator that serves no TLS (the key would cross the network in the clear)")
	noQR := fs.Bool("no-qr", false, "print the link without the QR code")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintln(os.Stderr, "calabi-coord invite:", err)
		return 1
	}
	if strings.TrimSpace(*server) == "" {
		return fail(errors.New("which address do devices dial? pass --server host:port, or set CALABI_COORD_PUBLIC_ADDR"))
	}
	if _, _, err := net.SplitHostPort(*server); err != nil {
		return fail(fmt.Errorf("--server %q is not host:port", *server))
	}
	c, err := af.client()
	if err != nil {
		return fail(err)
	}
	var tlsInfo struct {
		Mode string `json:"mode"`
		Pin  string `json:"pin"`
	}
	if err := c.do(http.MethodGet, "/admin/tls", nil, &tlsInfo); err != nil {
		return fail(err)
	}
	link := invite{server: strings.TrimSpace(*server)}
	if link.pin, link.plaintext, err = inviteTrust(tlsInfo.Mode, tlsInfo.Pin, *pin, *noPin, *allowPlaintext); err != nil {
		return fail(err)
	}

	var k cliAuthKey
	if err := c.do(http.MethodPost, fmt.Sprintf("/admin/meshnets/%d/authkeys", *af.meshnet), ko.request(), &k); err != nil {
		return fail(err)
	}
	link.key = k.Key

	fmt.Printf("Invite to meshnet %d: %s.\n\n", *af.meshnet, describeKey(k))
	fmt.Println(link.url())
	fmt.Println()
	if !*noQR {
		if err := writeQR(os.Stdout, link.url()); err != nil {
			fmt.Fprintln(os.Stderr, "calabi-coord invite: QR code:", err)
		}
		fmt.Println()
	}
	fmt.Println("On a phone: Calabi → Connect to a self-hosted server → scan the code, or open the link.")
	fmt.Println("On a computer: the client's console (http://127.0.0.1:7400) → Connect to a self-hosted server → paste the link, or")
	fmt.Println("  " + link.commandLine())
	fmt.Println()
	fmt.Println("The link carries the key: send it only to the person it is for. The key is not shown again.")
	return 0
}

// inviteTrust decides how an invite tells the device to trust the coordinator,
// from what the listener serves (GET /admin/tls): the fingerprint to pin, or
// plaintext, or neither — the system's roots.
//
//   - self-signed: pin it, unless --no-pin. Nothing else would verify it.
//   - a configured certificate: assume devices already trust it (a public CA),
//     unless --pin. Pinning a Let's Encrypt certificate would break every
//     device at its next renewal, which issues a new key.
//   - off: only with --allow-plaintext, since the key crosses in the clear.
func inviteTrust(mode, listenerPin string, forcePin, noPin, allowPlaintext bool) (pin string, plaintext bool, err error) {
	switch mode {
	case "off":
		if !allowPlaintext {
			return "", false, errors.New("this coordinator serves no TLS (CALABI_COORD_TLS=off), so the key would cross the network in the clear; " +
				"pass --allow-plaintext if devices reach it over a network you trust")
		}
		return "", true, nil
	case "self-signed":
		if noPin {
			return "", false, nil
		}
	default:
		if !forcePin {
			return "", false, nil
		}
	}
	if listenerPin == "" {
		return "", false, errors.New("the coordinator reported no certificate fingerprint")
	}
	return listenerPin, false, nil
}

// describeKey says what a key admits, for a person.
func describeKey(k cliAuthKey) string {
	who := "one device"
	switch {
	case k.MaxUses == 0:
		who = "any number of devices"
	case k.MaxUses > 1:
		who = fmt.Sprintf("up to %d devices", k.MaxUses)
	}
	until := "never expires"
	if k.ExpiresAtMS != 0 {
		until = "admits new devices until " + time.UnixMilli(k.ExpiresAtMS).Local().Format("2006-01-02 15:04 MST")
	}
	s := who + ", " + until
	if len(k.Tags) > 0 {
		s += ", tags " + strings.Join(k.Tags, ",")
	}
	return s
}

// invite is what a device needs to join: where, the key, and how to trust the
// server.
type invite struct {
	server    string
	key       string
	pin       string
	plaintext bool
}

// url is the calabi://join link the phone app opens and the QR code carries.
// Parameters: v (format version), s (server host:port), k (auth key), and one of
// fp (certificate fingerprint to pin) or tls=off; neither means "trust the
// system's roots".
func (i invite) url() string {
	q := url.Values{}
	q.Set("v", "1")
	q.Set("s", i.server)
	q.Set("k", i.key)
	if i.pin != "" {
		q.Set("fp", i.pin)
	}
	if i.plaintext {
		q.Set("tls", "off")
	}
	return "calabi://join?" + q.Encode()
}

// commandLine is the same invite for a computer's terminal: joining is the
// device's sign-in, for tunnels and the mesh alike. Double quotes, which every
// shell a desktop has takes as they are: the link carries &.
func (i invite) commandLine() string {
	return `calabi join "` + i.url() + `"`
}
