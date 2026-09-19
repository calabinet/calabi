package main

// How `calabi http|tcp|udp|sni` reach their edge and sign in there. On
// calabi.net: the edge's certificate checked against the CA compiled into this
// client, and the account's token. Self-hosted: the edge, its certificate and
// the sign-in all come from the coordinator this device joined — nothing in the
// environment names or trusts an edge any more.

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/calabi/calabi/apps/client/internal/mesh"
	"github.com/calabi/calabi/apps/client/internal/session"
)

// signInOneShot opens the edge as the one-shot commands do and signs in. It
// returns the session and the edge (closed when the test ends), and why it
// could not: the handshake's error, or what the command printed and its exit
// code.
func signInOneShot(t *testing.T) (*session.Client, *oneShotEdge, error) {
	t.Helper()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
	var edge *oneShotEdge
	var code int
	msg := captureStderr(t, func() { edge, code = openOneShotEdge(logger, "http") })
	if edge == nil {
		return nil, nil, fmt.Errorf("exit %d: %s", code, msg)
	}
	t.Cleanup(edge.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cli := edge.newSession(logger, "one-shot")
	if err := cli.Handshake(ctx); err != nil {
		return nil, edge, err
	}
	return cli, edge, nil
}

func writeCertPEM(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// joinedDevice makes this client a device that joined coord, with its mesh
// off: the console's config naming the coordinator, the record of which node it
// is, and its key.
func joinedDevice(t *testing.T, coord *fakeSHCoord) mesh.PrivateKey {
	t.Helper()
	keyFile := filepath.Join(t.TempDir(), "mesh.key")
	key, err := mesh.LoadOrCreateKey(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	cfg := localConfig{Mesh: meshConfig{Coord: coord.addr, Trust: "pin", Pins: []string{coord.pin}, KeyFile: keyFile}}
	if err := writeLocalConfig(managedConfigPath(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := saveMeshReauth(meshReauthRecord{Coord: coord.addr, NodeID: 21, Reauth: true}); err != nil {
		t.Fatal(err)
	}
	return key
}

// Platform mode is as it was: the compiled-in CA, plus CALABI_EDGE_CA_FILE for
// a development stack, and the account's token.
func TestOneShotPlatformModeKeepsTheCompiledInCA(t *testing.T) {
	isolateDataDir(t)
	t.Setenv("CALABI_MODE", clientModePlatform)
	e := startFakeEdge(t, "edge-token")
	t.Setenv("CALABI_SERVER", e.addr)
	t.Setenv("CALABI_API_KEY", "edge-token")
	edgeCA := writeCertPEM(t, e.cert.Load().Leaf)
	for _, tc := range []struct {
		name    string
		env     map[string]string
		trusted bool
	}{
		{"nothing set is verified, and this edge is not ours", nil, false},
		{"a pin is not read", map[string]string{"CALABI_EDGE_PIN": e.pin}, false},
		{"CALABI_EDGE_CA_FILE", map[string]string{"CALABI_EDGE_CA_FILE": edgeCA}, true},
		{"CALABI_INSECURE", map[string]string{"CALABI_INSECURE": "1"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			before := e.sessions()
			_, _, err := signInOneShot(t)
			if (err == nil) != tc.trusted {
				t.Fatalf("trusted = %v (err %v), want %v", err == nil, err, tc.trusted)
			}
			if !tc.trusted && !strings.Contains(err.Error(), "certificate") {
				t.Fatalf("err = %v, want it to be about the certificate", err)
			}
			if want := before + map[bool]int{true: 1}[tc.trusted]; e.sessions() != want {
				t.Fatalf("the edge authenticated %d sessions, want %d", e.sessions(), want)
			}
		})
	}

	// Exactly what the commands passed before, so transport adds the file to the
	// compiled-in CA rather than replacing it.
	t.Setenv("CALABI_EDGE_CA_FILE", edgeCA)
	opts := platformEdgeDialOptions(e.addr)
	if opts.TLSConfig != nil || opts.Insecure || opts.CACertFile != edgeCA || opts.Addr != e.addr {
		t.Fatalf("options = %+v, want {Addr: %s, CACertFile: %s}", opts, e.addr, edgeCA)
	}
}

// Standalone: the device signs in as itself — the coordinator's grant for its
// node key, and the key's proof — on the edge the coordinator names, pinned to
// the certificate the coordinator read. What used to name or trust an edge in
// the environment is not read.
func TestOneShotSelfHostedSignsInAsTheJoinedDevice(t *testing.T) {
	for _, standalone := range []struct {
		how string
		set func(t *testing.T)
	}{
		{"CALABI_MODE", func(t *testing.T) { t.Setenv("CALABI_MODE", clientModeStandalone) }},
		{"calabi mode standalone", func(t *testing.T) {
			if code := runMode([]string{clientModeStandalone}); code != 0 {
				t.Fatalf("calabi mode standalone: exit %d", code)
			}
		}},
	} {
		t.Run(standalone.how, func(t *testing.T) {
			isolateDataDir(t)
			standalone.set(t)
			coord := startFakeSHCoord(t, true)
			e := startFakeGrantEdge(t, coord.grantPub())
			coord.setEdge(e.addr, e.pin)
			key := joinedDevice(t, coord)
			t.Setenv("CALABI_SERVER", "127.0.0.1:1")
			t.Setenv("CALABI_API_KEY", "tk_not_for_this_edge")
			t.Setenv("CALABI_INSECURE", "1")

			_, oe, err := signInOneShot(t)
			if err != nil {
				t.Fatal(err)
			}
			if oe.addr != e.addr {
				t.Fatalf("dialled %s, want the coordinator's edge %s", oe.addr, e.addr)
			}
			if nodes := e.provedNodes(); len(nodes) != 1 || nodes[0] != key.Public() {
				t.Fatalf("the edge's session proved %v, want this device's node key %v", nodes, key.Public())
			}
		})
	}
}

func TestOneShotSelfHostedRefusals(t *testing.T) {
	isolateDataDir(t)
	coord := startFakeSHCoord(t, true)
	e := startFakeGrantEdge(t, coord.grantPub())

	// Not joined: said so, and no control plane is asked which edge to dial.
	d := newEdgeDirectory(t, edge(41, "edge-sfo.example.com:7443", "us-west"))
	releaseBuild(t, d)
	t.Setenv("CALABI_MODE", clientModeStandalone)
	if _, _, err := signInOneShot(t); err == nil || !strings.Contains(err.Error(), "exit 2") || !strings.Contains(err.Error(), "calabi join") {
		t.Fatalf("not joined: %v; want exit 2 naming calabi join", err)
	}
	if n := d.calls.Load(); n != 0 {
		t.Fatalf("/v1/edges was called %d time(s) from a standalone client", n)
	}

	joinedDevice(t, coord)
	refused := func(what, want string) {
		t.Helper()
		before := e.sessions()
		if _, _, err := signInOneShot(t); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: %v; want it to say %q", what, err, want)
		}
		if e.sessions() != before {
			t.Fatalf("%s: the edge authenticated a session", what)
		}
	}
	refused("the coordinator names no edge", "names no edge")

	coord.setEdge(e.addr, e.pin)
	coord.mu.Lock()
	coord.awaiting = true
	coord.mu.Unlock()
	refused("waiting for approval", "waiting for approval")
	coord.mu.Lock()
	coord.awaiting = false
	coord.mu.Unlock()

	// Another certificate than the coordinator read: nothing is sent to what answers.
	_, otherPin := testSelfSigned(t, "not the edge")
	coord.setEdge(e.addr, otherPin)
	refused("another certificate", "does not match the pinned fingerprint")

	// An edge that asks for no proof (calabi.net's kind): nothing to sign in with.
	tokenEdge := startFakeEdge(t, "tok")
	coord.setEdge(tokenEdge.addr, tokenEdge.pin)
	refused("a token edge", "asked for no proof")
	if tokenEdge.sessions() != 0 {
		t.Fatal("a token edge authenticated a device")
	}

	coord.setEdge(e.addr, e.pin)
	if _, _, err := signInOneShot(t); err != nil {
		t.Fatalf("the coordinator's edge again: %v", err)
	}
}

// A grant lasts an hour; a session outlives it by handing the edge a renewed one
// in time, and one that stops renewing is ended by the edge.
func TestOneShotRenewsItsGrant(t *testing.T) {
	isolateDataDir(t)
	t.Setenv("CALABI_MODE", clientModeStandalone)
	coord := startFakeSHCoord(t, true)
	coord.mu.Lock()
	coord.grantTTL = 3 * time.Second
	coord.mu.Unlock()
	e := startFakeGrantEdge(t, coord.grantPub())
	coord.setEdge(e.addr, e.pin)
	joinedDevice(t, coord)

	cli, oe, err := signInOneShot(t)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	oe.keepFresh(ctx, quietTestLogger(), cli)
	time.Sleep(6 * time.Second)
	if _, refreshes, expired := e.counts(); refreshes < 2 || expired != 0 {
		t.Fatalf("after two grant lifetimes: %d renewals, %d sessions ended; want 2+ and none", refreshes, expired)
	}
	cancel()
	waitFor(t, "the edge to end the session that stopped renewing", 6*time.Second, func() bool {
		_, _, expired := e.counts()
		return expired == 1
	})
}

func TestGrantRenewalTiming(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		left, renew, retry time.Duration
	}{
		{time.Hour, 40 * time.Minute, time.Minute},
		{90 * time.Second, time.Minute, 45 * time.Second},
		{3 * time.Second, 2 * time.Second, 1500 * time.Millisecond},
		{0, time.Second, time.Second},
		{-time.Minute, time.Second, time.Second}, // handed out already expired: no spinning
	} {
		exp := now.Add(tc.left)
		if got := grantRenewDelay(now, exp); got != tc.renew {
			t.Errorf("renew with %v left: %v, want %v", tc.left, got, tc.renew)
		}
		if got := grantRetryDelay(now, exp); got != tc.retry {
			t.Errorf("retry with %v left: %v, want %v", tc.left, got, tc.retry)
		}
	}
}
