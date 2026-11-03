//go:build linux

package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestBrowserAuthUnixIssuanceAndRevocation(t *testing.T) {
	dir, err := os.MkdirTemp("", "cba-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := newBrowserAuth()
	socket := filepath.Join(dir, "auth.sock")
	close, err := startBrowserAuth(ctx, socket, "http://127.0.0.1:7400/", a)
	if err != nil {
		t.Fatal(err)
	}
	defer close()
	st, _ := os.Stat(socket)
	if st.Mode().Perm() != 0600 {
		t.Fatal("unsafe authorization socket permissions")
	}
	link, err := browserAuthRequest(socket, "pair")
	if err != nil || !strings.Contains(link, "#/mesh/files?pair=") {
		t.Fatal(link, err)
	}
	pair := strings.Split(link, "pair=")[1]
	token, _, ok := a.exchange(pair, "127.0.0.1:7400", "test")
	if !ok {
		t.Fatal("pair failed")
	}
	if _, err = browserAuthRequest(socket, "revoke-all"); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.authorize(token, "127.0.0.1:7400", false); ok {
		t.Fatal("private revoke did not invalidate browser")
	}
	if ctx.Err() != nil {
		t.Fatal("authorization revoked agent lifetime")
	}
	if _, err = browserAuthRequest(filepath.Join(dir, "absent.sock"), "pair"); err == nil {
		t.Fatal("missing service accepted")
	}
	if _, err = startBrowserAuth(ctx, socket, "http://127.0.0.1:7400/", newBrowserAuth()); err == nil {
		t.Fatal("live authorization listener replaced")
	}
	// The public file handler has no pairing issuance endpoint, even for a
	// valid browser session and forged local-user headers.
	b := &fileBrowser{authority: "127.0.0.1:7400", auth: a}
	for _, path := range []string{"/pair", "/file-web/pair", "/file-web/revoke-all"} {
		r := httptest.NewRequest("POST", "http://127.0.0.1:7400"+path, strings.NewReader(`{"uid":0}`))
		r.Header.Set("Origin", "http://127.0.0.1:7400")
		r.Header.Set("X-User-ID", "0")
		w := httptest.NewRecorder()
		b.ServeHTTP(w, r)
		if w.Code == 200 {
			t.Fatal("public capability issuance", path)
		}
	}
}

func TestBrowserAuthUnixRejectsOtherUID(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires isolated root container for UID transition")
	}
	dir, err := os.MkdirTemp("", "cba-peer-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	a := newBrowserAuth()
	socket := filepath.Join(dir, "auth.sock")
	close, err := startBrowserAuth(context.Background(), socket, "http://127.0.0.1:7400/", a)
	if err != nil {
		t.Fatal(err)
	}
	defer close()
	// Deliberately open only this synthetic fixture's filesystem permissions;
	// SO_PEERCRED must still reject a different UID.
	if err = os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(socket, 0666); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestBrowserAuthOtherUIDHelper$")
	cmd.Env = append(os.Environ(), "CALABI_TEST_AUTH_SOCKET="+socket)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("kernel peer check failed: %v %s", err, out)
	}
}

func TestBrowserAuthOtherUIDHelper(t *testing.T) {
	socket := os.Getenv("CALABI_TEST_AUTH_SOCKET")
	if socket == "" {
		t.Skip("subprocess helper")
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer tr.CloseIdleConnections()
	r, err := (&http.Client{Transport: tr}).Post("http://auth/pair", "application/json", strings.NewReader(`{"uid":0}`))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != 403 {
		body, _ := io.ReadAll(r.Body)
		var ignored any
		_ = json.Unmarshal(body, &ignored)
		t.Fatalf("other UID was not rejected: %d", r.StatusCode)
	}
}
