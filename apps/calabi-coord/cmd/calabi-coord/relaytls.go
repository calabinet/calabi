package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// How a SELF-HOSTED coordinator's devices reach its relays over TLS.
//
// A relay presents its edge's own certificate on its data port — the same one
// that edge's control listener presents — so devices check a relay exactly the
// way this coordinator already tells them to check the edge (edgedir.go):
//
//   - CALABI_COORD_EDGE_TRUST=system: the system's roots and the host name;
//   - CALABI_COORD_EDGE_PIN: that fingerprint, for the relay on the edge's own
//     machine;
//   - otherwise: the fingerprint read off the relay itself, again every minute,
//     so a relay that makes itself a new certificate is followed.
//
// A relay on another machine (a multi-node CALABI_COORD_DERP_MAP_FILE) has no
// fingerprint to be given, so its own is read, the same way.
//
// A relay goes into the map as TLS only once this coordinator has actually
// completed a TLS handshake with it on its data port — a relay older than relay
// TLS never does, and stays plaintext — and only with a trust that its
// certificate passes: devices told a relay speaks TLS never fall back to
// plaintext, so a map entry they cannot verify would only strand them.

const (
	relayProbeEvery      = time.Minute
	relayProbeTimeout    = 10 * time.Second
	relayProbeUntilKnown = 5 * time.Second
)

// relayProbe is what one handshake with a relay's data port found.
type relayProbe struct {
	// tls: the relay completed a TLS handshake for the relay protocol.
	tls bool
	// pin is the fingerprint of the certificate it presented.
	pin string
	// systemOK: that certificate verifies against this machine's roots for the
	// host devices dial, as a device with trust=system would check it.
	systemOK bool
}

// errRelayUnreached is a relay the probe could not reach at all. It says
// nothing about the relay, so what was known before is kept — a relay that is
// down for a minute has not stopped speaking TLS.
var errRelayUnreached = errors.New("relay not reached")

// probeRelayTLS makes one TLS handshake with a relay's data port, for the
// relay protocol, and reports what it presented. Nothing is sent after the
// handshake. A relay that answers but not with TLS — one older than relay TLS
// hangs up on a ClientHello — is a plain result (tls false), not an error.
func probeRelayTLS(ctx context.Context, addr, host string) (relayProbe, error) {
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return relayProbe{}, errors.Join(errRelayUnreached, err)
	}
	defer raw.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	conn := tls.Client(raw, &tls.Config{
		ServerName: host, NextProtos: []string{meshproto.DERPALPN}, MinVersion: tls.VersionTLS13,
		// Only to read the certificate; which trust it passes is decided below,
		// and devices make their own check.
		InsecureSkipVerify: true, //nolint:gosec
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		var ne net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
			return relayProbe{}, errors.Join(errRelayUnreached, err)
		}
		return relayProbe{}, nil // answered, not with TLS
	}
	cs := conn.ConnectionState()
	if cs.NegotiatedProtocol != meshproto.DERPALPN || len(cs.PeerCertificates) == 0 {
		return relayProbe{}, nil
	}
	leaf := cs.PeerCertificates[0]
	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, verr := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter})
	return relayProbe{tls: true, pin: meshproto.CertPin(leaf), systemOK: verr == nil}, nil
}

// selfHostedRelays is a self-hosted coordinator's relay map: the operator's
// static map, with each relay marked TLS as found. Its Current feeds
// CompositeDERP.PlatformFn.
type selfHostedRelays struct {
	static core.DERPMap
	edges  *edgeDirectory // how the edge is trusted; nil = no edge configured
	logger *slog.Logger
	// probe is probeRelayTLS; a seam for tests.
	probe func(ctx context.Context, addr, host string) (relayProbe, error)
	// every / untilKnown override the probe cadence; for tests.
	every, untilKnown time.Duration

	mu    sync.RWMutex
	found map[string]relayProbe // by the address devices dial
	live  core.DERPMap
	// said is the TLS entry last logged per relay, so a steady state is quiet.
	said map[string]core.DERPTLS
}

func newSelfHostedRelays(static core.DERPMap, edges *edgeDirectory, logger *slog.Logger) *selfHostedRelays {
	return &selfHostedRelays{static: static, edges: edges, logger: logger, probe: probeRelayTLS,
		found: map[string]relayProbe{}, live: static, said: map[string]core.DERPTLS{}}
}

// Current is the map devices get now.
func (s *selfHostedRelays) Current() core.DERPMap {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.live
}

// probeAddr is where this coordinator reaches a relay. The relay on the edge's
// own machine is reached where the edge is (CALABI_COORD_EDGE_PROBE_ADDR, in a
// compose file 127.0.0.1): the public address is where devices reach it, and
// from inside that machine it may not route.
func (s *selfHostedRelays) probeAddr(n core.DERPNode) string {
	port := strconv.Itoa(n.DERPPort)
	if s.edges != nil && strings.EqualFold(hostOnly(s.edges.addr), n.HostName) {
		return net.JoinHostPort(hostOnly(s.edges.probeAddr), port)
	}
	return net.JoinHostPort(n.HostName, port)
}

// onEdge reports whether a relay runs on the edge's machine, and so presents
// the certificate the edge is trusted by.
func (s *selfHostedRelays) onEdge(n core.DERPNode) bool {
	return s.edges != nil && strings.EqualFold(hostOnly(s.edges.addr), n.HostName)
}

// trustFor is the TLS entry for a relay, from what its last handshake found.
// The zero value — plaintext — whenever devices could not verify it.
func (s *selfHostedRelays) trustFor(n core.DERPNode, p relayProbe) (core.DERPTLS, string) {
	switch {
	case !p.tls:
		return core.DERPTLS{}, "the relay does not speak TLS on its data port (older than relay TLS, or not reached yet)"
	case s.edges != nil && s.edges.system:
		if !p.systemOK {
			return core.DERPTLS{}, "the edge is trusted by the system's roots (" + envPrefix + "_" + edgeTrustEnv + "=system), and this relay's certificate does not verify against them for " + n.HostName
		}
		return core.DERPTLS{Trust: meshproto.RelayTrustSystem}, ""
	case s.onEdge(n) && s.edges.given:
		given := s.edges.givenPin()
		if p.pin != given {
			return core.DERPTLS{}, "the relay presents " + p.pin + ", not the fingerprint in " + envPrefix + "_" + edgePinEnv
		}
		return core.DERPTLS{Trust: meshproto.RelayTrustPin, Pins: []string{given}}, ""
	}
	return core.DERPTLS{Trust: meshproto.RelayTrustPin, Pins: []string{p.pin}}, ""
}

// refresh probes every relay once and rebuilds the map, reporting whether it
// changed. A relay that could not be reached keeps what was known about it.
func (s *selfHostedRelays) refresh(ctx context.Context) bool {
	next := core.DERPMap{Regions: make([]core.DERPRegion, 0, len(s.static.Regions))}
	type note struct {
		addr, why string
		tls       core.DERPTLS
	}
	var notes []note
	for _, r := range s.static.Regions {
		reg := core.DERPRegion{Code: r.Code, Nodes: make([]core.DERPNode, 0, len(r.Nodes))}
		for _, n := range r.Nodes {
			addr := net.JoinHostPort(n.HostName, strconv.Itoa(n.DERPPort))
			if !strings.HasSuffix(strings.ToLower(n.HostName), ".invalid") {
				pctx, cancel := context.WithTimeout(ctx, relayProbeTimeout)
				p, err := s.probe(pctx, s.probeAddr(n), n.HostName)
				cancel()
				if err == nil {
					s.mu.Lock()
					s.found[addr] = p
					s.mu.Unlock()
				}
			}
			s.mu.RLock()
			p := s.found[addr]
			s.mu.RUnlock()
			entry, why := s.trustFor(n, p)
			n.TLS = entry
			notes = append(notes, note{addr: addr, why: why, tls: entry})
			reg.Nodes = append(reg.Nodes, n)
		}
		next.Regions = append(next.Regions, reg)
	}

	s.mu.Lock()
	changed := !derpMapEqual(s.live, next)
	s.live = next
	var say []note
	for _, nt := range notes {
		if prev, ok := s.said[nt.addr]; !ok || !prev.Equal(nt.tls) {
			s.said[nt.addr] = nt.tls
			say = append(say, nt)
		}
	}
	s.mu.Unlock()
	for _, nt := range say {
		if nt.tls.Enabled() {
			s.logger.Info("coord: devices reach this relay over TLS", "relay", nt.addr, "trust", nt.tls.Trust, "pins", nt.tls.Pins)
		} else {
			s.logger.Info("coord: devices reach this relay in plaintext", "relay", nt.addr, "why", nt.why)
		}
	}
	return changed
}

// run keeps the map current until ctx ends, pushing every node a fresh netmap
// whenever a relay's TLS entry changes — a device never switches on its own,
// so it must be told at once rather than at the next periodic resend.
func (s *selfHostedRelays) run(ctx context.Context, notif *core.Notifier) {
	every, untilKnown := s.every, s.untilKnown
	if every == 0 {
		every = relayProbeEvery
	}
	if untilKnown == 0 {
		untilKnown = relayProbeUntilKnown
	}
	for {
		if s.refresh(ctx) {
			notif.BumpAll()
		}
		wait := every
		if !s.allKnown() {
			wait = untilKnown
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// allKnown reports whether every probe-able relay has answered once. Until then
// the probe runs fast: started together, the coordinator is often up before
// its relays listen, and devices joining in that first minute would otherwise
// wait a minute for TLS.
func (s *selfHostedRelays) allKnown() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.static.Regions {
		for _, n := range r.Nodes {
			if strings.HasSuffix(strings.ToLower(n.HostName), ".invalid") {
				continue
			}
			if _, ok := s.found[net.JoinHostPort(n.HostName, strconv.Itoa(n.DERPPort))]; !ok {
				return false
			}
		}
	}
	return true
}
