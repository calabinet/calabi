package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

const (
	pinA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	pinB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func setEdgeEnv(t *testing.T, addr, pin, trust, probe string) {
	t.Helper()
	t.Setenv(envPrefix+"_"+edgeAddrEnv, addr)
	t.Setenv(envPrefix+"_"+edgePinEnv, pin)
	t.Setenv(envPrefix+"_"+edgeTrustEnv, trust)
	t.Setenv(envPrefix+"_"+edgeProbeAddrEnv, probe)
}

// Settings that would hand devices a wrong answer stop the coordinator; no
// settings at all is no edge.
func TestEdgeDirectoryFromEnv(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		addr, pin, trust, probe  string
		wantErr, wantNil         bool
		wantSystem, wantLearns   bool
		wantPin, wantProbeTarget string
	}{
		{name: "nothing", wantNil: true},
		{name: "a pin without an edge", pin: pinA, wantErr: true},
		{name: "not host:port", addr: "edge.example.com", wantErr: true},
		{name: "a bad pin", addr: "edge.example.com:7443", pin: "sha256:zz", wantErr: true},
		{name: "system and a pin", addr: "edge.example.com:7443", pin: pinA, trust: "system", wantErr: true},
		{name: "unknown trust", addr: "edge.example.com:7443", trust: "ca", wantErr: true},
		{name: "a given pin", addr: "edge.example.com:7443", pin: pinA, wantPin: pinA, wantProbeTarget: "edge.example.com:7443"},
		{name: "system", addr: "edge.example.com:7443", trust: "system", wantSystem: true, wantProbeTarget: "edge.example.com:7443"},
		{name: "learned, read elsewhere", addr: "edge.example.com:7443", probe: "edge:7443", wantLearns: true, wantProbeTarget: "edge:7443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setEdgeEnv(t, tc.addr, tc.pin, tc.trust, tc.probe)
			d, err := edgeDirectoryFromEnv(quietLogger())
			switch {
			case tc.wantErr:
				if err == nil {
					t.Fatal("accepted")
				}
				return
			case err != nil:
				t.Fatal(err)
			case tc.wantNil:
				if d != nil {
					t.Fatalf("got %+v, want no edge", d)
				}
				return
			}
			if d.system != tc.wantSystem || d.learns() != tc.wantLearns || d.pin != tc.wantPin || d.probeAddr != tc.wantProbeTarget {
				t.Fatalf("system=%v learns=%v pin=%q probe=%q", d.system, d.learns(), d.pin, d.probeAddr)
			}
		})
	}
}

// Until the edge's certificate has been read there is no edge to name: devices
// would otherwise check it against their system roots. A failed read keeps what
// was known, and a new certificate replaces it.
func TestEdgeDirectoryFollowsTheCertificateItReads(t *testing.T) {
	answers := []struct {
		pin string
		err error
	}{
		{err: errors.New("connection refused")},
		{pin: pinA},
		{err: errors.New("timeout")},
		{pin: pinB},
	}
	d := &edgeDirectory{addr: "edge.example.com:7443", probeAddr: "edge:7443", logger: quietLogger()}
	d.probe = func(_ context.Context, addr string) (string, error) {
		if addr != "edge:7443" {
			t.Fatalf("read the certificate at %s, want the probe address", addr)
		}
		a := answers[0]
		answers = answers[1:]
		return a.pin, a.err
	}
	want := [][]core.Edge{
		nil,
		{{Addr: "edge.example.com:7443", Pin: pinA}},
		{{Addr: "edge.example.com:7443", Pin: pinA}},
		{{Addr: "edge.example.com:7443", Pin: pinB}},
	}
	for i, w := range want {
		d.refresh(context.Background())
		got := d.Edges()
		if len(got) != len(w) || (len(w) == 1 && got[0] != w[0]) {
			t.Fatalf("after read %d: edges = %v, want %v", i+1, got, w)
		}
	}
}

// Started together, the coordinator is up before the edge listens. It keeps
// trying every few seconds until it has read the certificate once — a device
// joining in the first minute must not wait for the next minute's read — and
// only then settles to once a minute.
func TestEdgeDirectoryFindsAnEdgeThatStartsLater(t *testing.T) {
	var mu sync.Mutex
	reads := 0
	d := &edgeDirectory{addr: "edge.example.com:7443", probeAddr: "127.0.0.1:7443", logger: quietLogger(),
		untilKnown: 10 * time.Millisecond}
	d.probe = func(context.Context, string) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		reads++
		if reads < 4 {
			return "", errors.New("connection refused")
		}
		return pinA, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.run(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for len(d.Edges()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the edge that started after the coordinator was not found within two seconds")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	n := reads
	mu.Unlock()
	if n != 4 {
		t.Fatalf("%d reads; once the certificate is known the next read is a minute away, want 4", n)
	}
}

// A given pin, or a public certificate, is not second-guessed by reading the
// edge.
func TestEdgeDirectoryDoesNotReadAGivenAnswer(t *testing.T) {
	for _, d := range []*edgeDirectory{
		{addr: "edge.example.com:7443", pin: pinA, given: true},
		{addr: "edge.example.com:7443", system: true},
	} {
		d.logger = quietLogger()
		d.probe = func(context.Context, string) (string, error) {
			t.Fatal("read the edge's certificate although the answer was given")
			return "", nil
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		d.run(ctx)
		if len(d.Edges()) != 1 {
			t.Fatalf("edges = %v", d.Edges())
		}
	}
	if got := (&edgeDirectory{addr: "edge.example.com:7443", system: true}).Edges(); got[0].Pin != "" {
		t.Fatalf("a public certificate is sent with pin %q", got[0].Pin)
	}
}

// What the coordinator reads is the fingerprint of the certificate the edge
// actually presents — the one a device then checks.
func TestReadEdgePinIsTheCertificatePresented(t *testing.T) {
	cert := selfSignedEdgeCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: edgeALPN,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.(*tls.Conn).Handshake()
			_ = c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := readEdgePin(ctx, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if want := meshproto.CertPin(cert.Leaf); got != want {
		t.Fatalf("pin = %s, want %s", got, want)
	}
}

func selfSignedEdgeCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "edge"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}
