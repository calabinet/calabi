package main

import (
	"bytes"
	"context"
	"io"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/adminhttp"
	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	"rsc.io/qr"
)

// captureStdout runs f and returns what it printed.
func captureStdout(t *testing.T, f func() int) (string, int) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	code := f()
	os.Stdout = old
	_ = w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String(), code
}

// `calabi-coord invite` against a running coordinator's admin API: the link it
// prints carries a key the coordinator accepts, and the fingerprint the
// listener actually serves.
func TestInviteEndToEnd(t *testing.T) {
	coord := &core.Coordinator{
		Nodes:       core.NewMemNodeStore(),
		AuthKeys:    core.NewMemAuthKeyStore(),
		ListenerTLS: core.ListenerTLS{Mode: "self-signed", Pin: "sha256:" + strings.Repeat("cd", 32)},
		Logger:      quietLogger(),
	}
	srv := httptest.NewServer(adminhttp.New(coord, core.NewNotifier(), quietLogger()))
	defer srv.Close()

	out, code := captureStdout(t, func() int {
		return runInvite([]string{"--admin", srv.URL, "--token", "t", "--server", "coord.example.com:7012",
			"--tag", "tag:phone", "--note", "alice", "--no-qr"})
	})
	if code != 0 {
		t.Fatalf("invite exited %d:\n%s", code, out)
	}
	var link string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "calabi://join?") {
			link = line
		}
	}
	u, err := url.Parse(link)
	if err != nil || link == "" {
		t.Fatalf("no link in:\n%s", out)
	}
	q := u.Query()
	if q.Get("v") != "1" || q.Get("s") != "coord.example.com:7012" || q.Get("fp") != coord.ListenerTLS.Pin || q.Get("tls") != "" {
		t.Fatalf("link %s", link)
	}
	auth := &core.KeyAuth{Keys: coord.AuthKeys}
	id, err := auth.Resolve(context.Background(), q.Get("k"))
	if err != nil || id.Meshnet != 1 || len(id.Tags) != 1 || id.Tags[0] != "tag:phone" {
		t.Fatalf("the invited key resolves to %+v, %v", id, err)
	}
	if !strings.Contains(out, `calabi join "`+link+`"`) {
		t.Fatalf("no matching command line in:\n%s", out)
	}
}

func TestInviteTrust(t *testing.T) {
	pin := "sha256:" + strings.Repeat("ef", 32)
	for _, tc := range []struct {
		name                  string
		mode                  string
		force, no, allowPlain bool
		wantPin               string
		wantPlain, wantErr    bool
	}{
		{name: "self-signed pins", mode: "self-signed", wantPin: pin},
		{name: "self-signed, --no-pin", mode: "self-signed", no: true},
		{name: "configured certificate trusts the system", mode: "files"},
		{name: "configured certificate, --pin", mode: "files", force: true, wantPin: pin},
		{name: "plaintext refused", mode: "off", wantErr: true},
		{name: "plaintext allowed", mode: "off", allowPlain: true, wantPlain: true},
	} {
		gotPin, gotPlain, err := inviteTrust(tc.mode, pin, tc.force, tc.no, tc.allowPlain)
		if (err != nil) != tc.wantErr || gotPin != tc.wantPin || gotPlain != tc.wantPlain {
			t.Errorf("%s: pin %q plaintext %v err %v", tc.name, gotPin, gotPlain, err)
		}
	}
}

func TestInviteLinkAndCommandLine(t *testing.T) {
	plain := invite{server: "10.0.0.5:7012", key: "ck_abc", plaintext: true}
	if u := plain.url(); !strings.Contains(u, "tls=off") || strings.Contains(u, "fp=") {
		t.Fatalf("plaintext link %s", u)
	}
	if c := plain.commandLine(); c != `calabi join "`+plain.url()+`"` {
		t.Fatalf("plaintext command %q", c)
	}
	system := invite{server: "coord.example.com:443", key: "ck_abc"}
	if c := system.commandLine(); c != `calabi join "calabi://join?k=ck_abc&s=coord.example.com%3A443&v=1"` {
		t.Fatalf("system-trust command %q", c)
	}
}

func TestAdminBaseURL(t *testing.T) {
	for in, want := range map[string]string{
		":9500":                  "http://127.0.0.1:9500",
		"0.0.0.0:9500":           "http://127.0.0.1:9500",
		"10.0.0.2:9500":          "http://10.0.0.2:9500",
		"http://admin.lan:9500/": "http://admin.lan:9500",
	} {
		if got := adminBaseURL(in); got != want {
			t.Errorf("adminBaseURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// Read the drawing back, cell by cell, into modules and compare with the code
// the encoder produced: a transposed or inverted drawing is a QR code no phone
// can scan, and nothing else here would notice.
func TestWriteQRDrawsTheCode(t *testing.T) {
	text := "calabi://join?v=1&s=coord.example.com:7012&k=ck_x"
	var b bytes.Buffer
	if err := writeQR(&b, text); err != nil {
		t.Fatal(err)
	}
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		t.Fatal(err)
	}
	const quiet = 4
	size := code.Size + 2*quiet
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	if len(lines) != (size+1)/2 {
		t.Fatalf("%d lines, want %d", len(lines), (size+1)/2)
	}
	for row, line := range lines {
		cells := strings.Split(strings.TrimSuffix(line, "\x1b[0m"), "▀")
		cells = cells[:len(cells)-1] // after the last ▀ there is nothing
		if len(cells) != size {
			t.Fatalf("line %d has %d cells, want %d", row, len(cells), size)
		}
		for x, cell := range cells {
			top, bottom := strings.Contains(cell, "[30;"), strings.HasSuffix(cell, ";40m")
			for i, got := range []bool{top, bottom} {
				y := row*2 + i
				if y >= size {
					continue
				}
				mx, my := x-quiet, y-quiet
				want := mx >= 0 && my >= 0 && mx < code.Size && my < code.Size && code.Black(mx, my)
				if got != want {
					t.Fatalf("module (%d,%d): dark=%v, want %v", x, y, got, want)
				}
			}
		}
	}
}

// With a database, a coordinator with no key file admits nobody by default —
// the built-in key printed in the public source is only for a throwaway run.
func TestDatabaseTurnsTheBuiltInKeyOff(t *testing.T) {
	t.Setenv(envPrefix+"_AUTHKEYS_FILE", "")
	t.Setenv(legacyEnvPrefix+"_AUTHKEYS_FILE", "")
	ctx := context.Background()

	throwaway, err := selfHostedAuth(quietLogger(), core.NewMemAuthKeyStore(), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := throwaway.Resolve(ctx, "dev-meshnet-1-key"); err != nil {
		t.Fatalf("control: the dev key works on a coordinator without a database: %v", err)
	}
	durable, err := selfHostedAuth(quietLogger(), core.NewMemAuthKeyStore(), true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := durable.Resolve(ctx, "dev-meshnet-1-key"); err == nil {
		t.Fatal("the built-in dev key admits callers on a coordinator with a database")
	}
}
