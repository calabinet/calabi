package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// A self-hosted coordinator marks a relay TLS once it has completed a TLS
// handshake with it, and hands devices the trust its edge already has
// (relaytls.go). These cover the handshake against real listeners and the
// decisions against a fake one.

// relayListener serves the relay's side of a TLS handshake for the relay
// protocol, or — tls=false — behaves like a relay older than relay TLS: it
// reads the ClientHello as a frame header and hangs up.
func relayListener(t *testing.T, cert tls.Certificate, speaksTLS bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if !speaksTLS {
					var hdr [5]byte
					_, _ = io.ReadFull(c, hdr[:])
					return
				}
				tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13,
					NextProtos: []string{meshproto.DERPALPN}})
				_ = tc.Handshake()
			}()
		}
	}()
	return ln.Addr().String()
}

func TestProbeRelayTLSTellsTheThreeCasesApart(t *testing.T) {
	cert := selfSignedEdgeCert(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	p, err := probeRelayTLS(ctx, relayListener(t, cert, true), "127.0.0.1")
	if err != nil || !p.tls || p.pin != meshproto.CertPin(cert.Leaf) {
		t.Fatalf("TLS relay: %+v, %v; want tls with the certificate's pin", p, err)
	}
	if p.systemOK {
		t.Fatal("a self-signed certificate verified against the system's roots")
	}

	p, err = probeRelayTLS(ctx, relayListener(t, cert, false), "127.0.0.1")
	if err != nil || p.tls {
		t.Fatalf("relay older than TLS: %+v, %v; want a plain no, not an error", p, err)
	}

	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := closed.Addr().String()
	_ = closed.Close()
	if _, err := probeRelayTLS(ctx, addr, "127.0.0.1"); !errors.Is(err, errRelayUnreached) {
		t.Fatalf("nothing listening: err = %v, want errRelayUnreached", err)
	}
}

// fakeRelays answers probes from a table and records where each went.
type fakeRelays struct {
	mu    sync.Mutex
	by    map[string]relayProbe // by probe address
	down  map[string]bool
	asked []string
}

func (f *fakeRelays) probe(_ context.Context, addr, _ string) (relayProbe, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, addr)
	if f.down[addr] {
		return relayProbe{}, errRelayUnreached
	}
	return f.by[addr], nil
}

func oneRelayMap(host string) core.DERPMap {
	return core.DERPMap{Regions: []core.DERPRegion{{Code: "default", Nodes: []core.DERPNode{{HostName: host, DERPPort: 3340, STUNPort: 3478}}}}}
}

func entryOf(m core.DERPMap) core.DERPTLS { return m.Regions[0].Nodes[0].TLS }

// The trust a relay gets is the trust the edge has — and only if the relay's
// certificate passes it, since devices never fall back.
func TestSelfHostedRelayTrustFollowsTheEdge(t *testing.T) {
	for _, tc := range []struct {
		name  string
		edges *edgeDirectory
		found relayProbe
		want  core.DERPTLS
	}{
		{"no edge configured: the pin read off the relay",
			nil, relayProbe{tls: true, pin: pinA}, core.DERPTLS{Trust: meshproto.RelayTrustPin, Pins: []string{pinA}}},
		{"edge fingerprint learned: the relay's, read the same way",
			&edgeDirectory{addr: "relay.example:7443", probeAddr: "127.0.0.1:7443"}, relayProbe{tls: true, pin: pinA},
			core.DERPTLS{Trust: meshproto.RelayTrustPin, Pins: []string{pinA}}},
		{"EDGE_PIN given, relay presents it",
			&edgeDirectory{addr: "relay.example:7443", probeAddr: "127.0.0.1:7443", pin: pinA, given: true}, relayProbe{tls: true, pin: pinA},
			core.DERPTLS{Trust: meshproto.RelayTrustPin, Pins: []string{pinA}}},
		{"EDGE_PIN given, relay presents another",
			&edgeDirectory{addr: "relay.example:7443", probeAddr: "127.0.0.1:7443", pin: pinA, given: true}, relayProbe{tls: true, pin: pinB},
			core.DERPTLS{}},
		{"EDGE_TRUST=system, certificate public",
			&edgeDirectory{addr: "relay.example:7443", probeAddr: "127.0.0.1:7443", system: true}, relayProbe{tls: true, pin: pinA, systemOK: true},
			core.DERPTLS{Trust: meshproto.RelayTrustSystem}},
		{"EDGE_TRUST=system, certificate not public",
			&edgeDirectory{addr: "relay.example:7443", probeAddr: "127.0.0.1:7443", system: true}, relayProbe{tls: true, pin: pinA},
			core.DERPTLS{}},
		{"relay older than TLS",
			&edgeDirectory{addr: "relay.example:7443", probeAddr: "127.0.0.1:7443"}, relayProbe{}, core.DERPTLS{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeRelays{by: map[string]relayProbe{}}
			s := newSelfHostedRelays(oneRelayMap("relay.example"), tc.edges, quietLogger())
			s.probe = f.probe
			for _, a := range []string{"127.0.0.1:3340", "relay.example:3340"} {
				f.by[a] = tc.found
			}
			s.refresh(context.Background())
			if got := entryOf(s.Current()); !got.Equal(tc.want) {
				t.Fatalf("entry = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// The relay on the edge's own machine is reached where the edge is — from
// inside that machine the public address may not route — and another relay at
// its own address.
func TestSelfHostedRelayProbeAddress(t *testing.T) {
	f := &fakeRelays{by: map[string]relayProbe{}}
	m := core.DERPMap{Regions: []core.DERPRegion{
		{Code: "home", Nodes: []core.DERPNode{{HostName: "203.0.113.9", DERPPort: 3340}}},
		{Code: "tokyo", Nodes: []core.DERPNode{{HostName: "198.51.100.4", DERPPort: 3340}}},
		{Code: "placeholder", Nodes: []core.DERPNode{{HostName: "derp-lax.invalid", DERPPort: 443}}},
	}}
	s := newSelfHostedRelays(m, &edgeDirectory{addr: "203.0.113.9:7443", probeAddr: "127.0.0.1:7443"}, quietLogger())
	s.probe = f.probe
	s.refresh(context.Background())
	got := strings.Join(f.asked, " ")
	if got != "127.0.0.1:3340 198.51.100.4:3340" {
		t.Fatalf("probed %q, want the edge's relay at the probe host and the other at its own address, and no .invalid host", got)
	}
}

// A relay that cannot be reached keeps what was known: one that is down for a
// minute has not stopped speaking TLS. One that answers without TLS — the
// binary was replaced by an older one — goes back to plaintext at once, and so
// does a certificate change that no longer passes. Every change is reported,
// so the caller pushes it rather than waiting for the periodic resend.
func TestSelfHostedRelayStateAcrossProbes(t *testing.T) {
	f := &fakeRelays{by: map[string]relayProbe{"relay.example:3340": {tls: true, pin: pinA}}, down: map[string]bool{}}
	s := newSelfHostedRelays(oneRelayMap("relay.example"), nil, quietLogger())
	s.probe = f.probe

	if !s.refresh(context.Background()) || !entryOf(s.Current()).Enabled() {
		t.Fatal("first TLS answer: want a change to a TLS entry")
	}
	f.down["relay.example:3340"] = true
	if s.refresh(context.Background()) || !entryOf(s.Current()).Enabled() {
		t.Fatal("unreachable relay: want the TLS entry kept and no change")
	}
	f.down["relay.example:3340"] = false
	f.by["relay.example:3340"] = relayProbe{tls: true, pin: pinB}
	if !s.refresh(context.Background()) || entryOf(s.Current()).Pins[0] != pinB {
		t.Fatalf("new certificate: want a change to its pin, got %+v", entryOf(s.Current()))
	}
	f.by["relay.example:3340"] = relayProbe{}
	if !s.refresh(context.Background()) || entryOf(s.Current()).Enabled() {
		t.Fatal("answers without TLS: want a change back to plaintext")
	}
}
