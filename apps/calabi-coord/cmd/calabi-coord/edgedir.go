package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// The edge a self-hosted coordinator's devices serve tunnels through, from the environment:
//
//	CALABI_COORD_EDGE_ADDR        host:port of the edge's control listener, as devices reach it
//	CALABI_COORD_EDGE_PIN         the fingerprint of the edge's certificate, sha256:… (optional)
//	CALABI_COORD_EDGE_TRUST       "system": the edge has a publicly trusted certificate, checked
//	                              against each device's roots and the host name; no pin is sent
//	CALABI_COORD_EDGE_PROBE_ADDR  where THIS coordinator reaches the edge, when that is not
//	                              EDGE_ADDR (in a compose file: edge:7443). Default EDGE_ADDR
//
// With neither a pin nor trust=system, the coordinator connects to the edge,
// takes the fingerprint of the certificate it presents, and looks again every
// minute. An edge that makes itself a new certificate is then followed without
// anyone confirming anything: devices trust the edge through this coordinator,
// which they have already pinned. It is trust on first use between the
// coordinator and the edge, so it belongs where the two share a network nobody
// else is on — one host, one compose network. Across the internet, give the pin.

const (
	edgeAddrEnv      = "EDGE_ADDR"
	edgePinEnv       = "EDGE_PIN"
	edgeTrustEnv     = "EDGE_TRUST"
	edgeProbeAddrEnv = "EDGE_PROBE_ADDR"

	edgeProbeEvery   = time.Minute
	edgeProbeTimeout = 10 * time.Second
	// edgeProbeUntilKnown is how often the edge is tried until its certificate
	// has been read once. Started together (deploy/server), the coordinator is
	// often up before the edge listens; a device joining in that first minute
	// would otherwise be told of no edge until the next minute's read.
	edgeProbeUntilKnown = 5 * time.Second
)

// edgeALPN is what the edge's control listener speaks (the client offers the
// same, internal/selfhosted.EdgeALPN).
var edgeALPN = []string{"calabi/1"}

// edgeDirectory is the one configured edge, as core.EdgeDirectory.
type edgeDirectory struct {
	addr      string
	probeAddr string
	system    bool
	given     bool // the pin came from the environment
	logger    *slog.Logger
	// probe reads the fingerprint the edge presents; a seam for tests.
	probe func(ctx context.Context, addr string) (string, error)
	// untilKnown overrides edgeProbeUntilKnown; for tests.
	untilKnown time.Duration
	// warned: "cannot reach the edge" was logged, so the retries until it
	// answers do not repeat it.
	warned bool

	mu  sync.RWMutex
	pin string // "" until known, unless system
}

// edgeDirectoryFromEnv reads the edge's settings. Nil, nil when no edge is
// configured; an error for settings that would hand devices a wrong answer.
func edgeDirectoryFromEnv(logger *slog.Logger) (*edgeDirectory, error) {
	addr := strings.TrimSpace(env(edgeAddrEnv))
	pin := strings.TrimSpace(env(edgePinEnv))
	trust := strings.ToLower(strings.TrimSpace(env(edgeTrustEnv)))
	probeAddr := strings.TrimSpace(env(edgeProbeAddrEnv))
	if addr == "" {
		if pin != "" || trust != "" || probeAddr != "" {
			return nil, fmt.Errorf("%s_%s, _%s or _%s is set without %s_%s: which edge are they about?",
				envPrefix, edgePinEnv, edgeTrustEnv, edgeProbeAddrEnv, envPrefix, edgeAddrEnv)
		}
		return nil, nil
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return nil, fmt.Errorf("%s_%s %q is not host:port", envPrefix, edgeAddrEnv, addr)
	}
	d := &edgeDirectory{addr: addr, probeAddr: addr, logger: logger, probe: readEdgePin}
	if probeAddr != "" {
		if _, _, err := net.SplitHostPort(probeAddr); err != nil {
			return nil, fmt.Errorf("%s_%s %q is not host:port", envPrefix, edgeProbeAddrEnv, probeAddr)
		}
		d.probeAddr = probeAddr
	}
	switch trust {
	case "", "pin":
	case "system":
		if pin != "" {
			return nil, fmt.Errorf("%s_%s=system and a pin at once: devices would be told two different ways to check the edge", envPrefix, edgeTrustEnv)
		}
		d.system = true
	default:
		return nil, fmt.Errorf("%s_%s %q: want system or pin", envPrefix, edgeTrustEnv, trust)
	}
	if pin != "" {
		p, err := meshproto.ParseCertPin(pin)
		if err != nil {
			return nil, fmt.Errorf("%s_%s: %w", envPrefix, edgePinEnv, err)
		}
		d.pin, d.given = p, true
	}
	return d, nil
}

// learns reports whether the fingerprint is found by connecting to the edge.
func (d *edgeDirectory) learns() bool { return !d.system && !d.given }

// Edges is core.EdgeDirectory. Until the fingerprint is known there is nothing
// to say: an edge without a pin would be checked against the system's roots,
// and a self-signed edge would fail that — or, worse, something else answering
// at its address with a public certificate would pass.
func (d *edgeDirectory) Edges() []core.Edge {
	if d == nil {
		return nil
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	switch {
	case d.system:
		return []core.Edge{{Addr: d.addr}}
	case d.pin == "":
		return nil
	}
	return []core.Edge{{Addr: d.addr, Pin: d.pin}}
}

// run keeps a learned fingerprint current until ctx ends. Nothing to do when
// the pin was given or the edge's certificate is public.
func (d *edgeDirectory) run(ctx context.Context) {
	if d == nil || !d.learns() {
		return
	}
	for {
		d.refresh(ctx)
		wait := edgeProbeEvery
		if len(d.Edges()) == 0 {
			wait = d.untilKnown
			if wait == 0 {
				wait = edgeProbeUntilKnown
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// refresh reads the edge's certificate once. A failure keeps the fingerprint it
// had: an edge that is down for a minute has not changed its certificate.
func (d *edgeDirectory) refresh(ctx context.Context) {
	pctx, cancel := context.WithTimeout(ctx, edgeProbeTimeout)
	defer cancel()
	pin, err := d.probe(pctx, d.probeAddr)
	d.mu.Lock()
	was := d.pin
	if err == nil {
		d.pin = pin
	}
	d.mu.Unlock()
	switch {
	case err != nil && was == "" && !d.warned:
		d.warned = true
		d.logger.Warn("coord: cannot reach the edge to read its certificate; devices are told of no edge until it answers",
			"edge", d.probeAddr, "err", err)
	case err != nil:
		d.logger.Debug("coord: edge certificate check failed; keeping the fingerprint it had", "edge", d.probeAddr, "err", err)
	case was == "":
		d.logger.Info("coord: edge for tunnels", "addr", d.addr, "fingerprint", pin, "read_from", d.probeAddr)
	case was != pin:
		d.logger.Warn("coord: the edge presents a new certificate; devices follow it",
			"addr", d.addr, "was", was, "now", pin)
	}
}

// readEdgePin connects to the edge and returns the fingerprint of the
// certificate it presents, without sending anything.
func readEdgePin(ctx context.Context, addr string) (string, error) {
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer raw.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	conn := tls.Client(raw, &tls.Config{
		NextProtos: edgeALPN, MinVersion: tls.VersionTLS13,
		// Only to read the certificate — its fingerprint is the answer. The
		// connection closes without a byte of application data.
		InsecureSkipVerify: true, //nolint:gosec
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		return "", err
	}
	chain := conn.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return "", errors.New("the edge presented no certificate")
	}
	return meshproto.CertPin(chain[0]), nil
}

// withEdgeDirectory keeps the edge's fingerprint current for the service's
// lifetime, then runs next.
func withEdgeDirectory(d *edgeDirectory, next func(context.Context) error) func(context.Context) error {
	return func(ctx context.Context) error {
		if d != nil {
			go d.run(ctx)
		}
		return next(ctx)
	}
}

// edgeDirectoryOf is the directory wire() configured, or nil.
func edgeDirectoryOf(coord *core.Coordinator) *edgeDirectory {
	d, _ := coord.Edges.(*edgeDirectory)
	return d
}
