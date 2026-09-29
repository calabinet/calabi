package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/calabinet/calabi/apps/calabi-edge/internal/config"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	"github.com/calabinet/calabi/pkg/relay"
	"github.com/calabinet/calabi/pkg/stunserver"
)

// relayWiring is what the control-plane layer hands the relay. Every field is
// optional; the zero value is a relay with no control plane at all.
type relayWiring struct {
	// reporter (nil when self-hosted / when the node has no single org)
	// periodically drains the hub and re-sends this node's OWN relay usage as a
	// self-<label> region (edge/derp merge).
	reporter *relayUsageReporter
	// rate resolves each link's rate limiter. nil = no limiting, which is the
	// self-hosted posture and what every relay did before 2026-09-20.
	rate *relayRateResolver
	// admission is set for a node's own relay on calabi.net (config.BYOIRelay):
	// what its registration hears back about admitting devices
	// (relayadmission.go).
	admission *relayAdmission
	// org is the organization this node's certificate names, the only one such a
	// relay admits. 0 when the certificate names none.
	org int64
	// cert is the node's control certificate as its listener serves it
	// (controlCert.certificate): what the relay port presents to devices that
	// open TLS (relaytls.go). nil: the port speaks plaintext only.
	cert func(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

// runRelay serves the mesh-relay (calabi-derp) datapath in-process when role is
// "relay" or "both" — the edge/derp merge.
// It reuses the SAME pkg/relay hub + pkg/stunserver that the standalone
// standalone derp-node binary used to run before it was retired; only the
// assembly differs.
//
// DELIBERATELY ciphertext-only: the hub relays already-encrypted mesh packets by
// node key (pkg/relay never decrypts). The relay port terminates TLS of its own
// (relaytls.go) — the link to the device, with the node's control certificate —
// but nothing here touches the tunnel's TLS-terminating listeners, and pkg/relay
// sees a connection only after its handshake. Isolation is enforced
// structurally — pkg/relay's module graph carries no edge/control-plane code
// (pkg/relay/deps_test.go) — so the tunnel and relay datapaths cannot cross.
//
// A node's own relay on calabi.net does not listen until it knows how to check
// its devices: see awaitRelayAdmission.
//
// Blocks until ctx is cancelled, then tears its listeners down.
func runRelay(ctx context.Context, rc config.MeshService, logger *slog.Logger, w relayWiring) error {
	auth, follow, err := relayStartAuth(rc, w, logger)
	if err != nil {
		return err
	}
	if follow {
		key, ok := awaitRelayAdmission(ctx, w.admission, logger)
		if !ok {
			return nil // shut down while waiting
		}
		auth = admittedBy(auth, key)
	}
	logger.Info("mesh role: starting mesh-relay datapath",
		"derp_port", rc.RelayDERPPort(), "stun_port", rc.RelaySTUNPort(),
		"kind", auth.Kind, "require_auth", auth.Require, "label", rc.Label,
		"tls", w.cert != nil, "require_tls", rc.RequireTLS,
		"usage_report", w.reporter != nil, "rate_limit", w.rate != nil)
	if w.admission != nil {
		logRelayAdmission(logger, auth)
	}

	// STUN responder (UDP) — best-effort, mirrors calabi-derp. 0 disables it.
	if rc.RelaySTUNPort() > 0 {
		stunAddr := ":" + strconv.Itoa(rc.RelaySTUNPort())
		if ua, uerr := net.ResolveUDPAddr("udp", stunAddr); uerr != nil {
			logger.Warn("mesh role: STUN disabled (bad stun_port)", "addr", stunAddr, "err", uerr)
		} else if sc, lerr := net.ListenUDP("udp", ua); lerr != nil {
			logger.Warn("mesh role: STUN disabled (bind failed)", "addr", stunAddr, "err", lerr)
		} else {
			logger.Info("mesh role: STUN responder listening", "addr", stunAddr)
			go stunserver.Serve(sc, logger)
			go func() { <-ctx.Done(); _ = sc.Close() }()
		}
	} else {
		logger.Warn("mesh role: STUN responder off (stun_port 0): devices cannot measure this relay, so none picks it as home over a relay it can measure")
	}

	// Relay data port (TCP) — the address mesh nodes dial. Ciphertext in and out.
	derpAddr := ":" + strconv.Itoa(rc.RelayDERPPort())
	ln, err := relayListen(derpAddr)
	if err != nil {
		return fmt.Errorf("relay listen %s: %w", derpAddr, err)
	}
	logger.Info("mesh role: relay listening", "addr", derpAddr, "tls", w.cert != nil, "require_tls", rc.RequireTLS)
	rt := &relayTLS{cert: w.cert, requireTLS: rc.RequireTLS, logger: logger}
	return serveRelay(ctx, ln, auth, follow, logger, w, rt)
}

// relayListen binds the relay's data port. A var so a test can hand runRelay a
// loopback listener, and see when it is asked for one.
var relayListen = func(addr string) (net.Listener, error) { return net.Listen("tcp", addr) }

// serveRelay runs the relay on ln until ctx is cancelled. follow says the
// relay's admission comes from the platform's answers (a node's own relay with
// no key in its config), and keeps tracking them. rt opens each connection:
// TLS or plaintext, by its first byte (relaytls.go).
func serveRelay(ctx context.Context, ln net.Listener, auth relay.AuthConfig, follow bool, logger *slog.Logger, w relayWiring, rt *relayTLS) error {
	gens := newRelayGens(ctx, logger, w.rate)
	gens.start(auth)
	defer gens.stop()
	if w.reporter != nil {
		go w.reporter.reportLoop(ctx, gens.takeUsage)
	}
	if w.admission != nil {
		go followRelayAdmission(ctx, w.admission, gens, auth, follow, logger)
	}

	go rt.logLoop(ctx)

	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		conn, aerr := ln.Accept()
		if aerr != nil {
			if ctx.Err() != nil {
				return nil // clean shutdown
			}
			logger.Warn("mesh role: accept error", "err", aerr)
			continue
		}
		go rt.accept(ctx, conn, gens)
	}
}

// relayAuthConfig builds the auth posture from the relay config, mirroring
// the retired calabi-derp's authConfig (its DERP_NODE_KIND / _REQUIRE_AUTH /
// _COORD_PUBKEY are now relay.kind / .require_auth / .coord_pubkey).
// Kind defaults to "self": a merged BYOI node's relay is the org's own relay, and
// defaulting to platform would let it serve traffic an over-quota grant meant to
// stop.
func relayAuthConfig(rc config.MeshService) (relay.AuthConfig, error) {
	auth, err := relayKindAndKey(rc)
	if err != nil {
		return relay.AuthConfig{}, err
	}
	auth.Require = rc.RequireAuth
	// A relay that requires grants but can't verify one would black-hole every
	// connection. Refuse rather than start silently broken.
	if auth.Require && auth.CoordPub == nil {
		return relay.AuthConfig{}, fmt.Errorf("relay.require_auth is set but relay.coord_pubkey is empty; every connection would be rejected")
	}
	return auth, nil
}

// relayKindAndKey reads what the relay is and the coordinator key it was
// configured with, if any.
func relayKindAndKey(rc config.MeshService) (relay.AuthConfig, error) {
	var auth relay.AuthConfig
	switch strings.ToLower(strings.TrimSpace(rc.Kind)) {
	case "", "self", "self-hosted", "selfhosted":
		auth.Kind = meshproto.RelayKindSelfHosted
	case "platform":
		auth.Kind = meshproto.RelayKindPlatform
	default:
		return relay.AuthConfig{}, fmt.Errorf("relay.kind %q must be \"self\" or \"platform\"", rc.Kind)
	}
	if rc.CoordPubKey != "" {
		pub, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(rc.CoordPubKey))
		if derr != nil || len(pub) != ed25519.PublicKeySize {
			return relay.AuthConfig{}, fmt.Errorf("relay.coord_pubkey must be a base64 ed25519 public key (len=%d): %w", len(pub), derr)
		}
		auth.CoordPub = pub
	}
	return auth, nil
}

// relayStartAuth is the posture the relay starts from, and whether it follows
// the platform's answers from there (follow: a node's own relay on calabi.net
// whose config names no key — the key has yet to come from its registration).
//
// A node's own relay always checks grants and admits its organization's only.
// A key in its config is used as given, and then the relay neither waits for
// the platform nor follows it (followRelayAdmission only says so when the two
// keys differ).
func relayStartAuth(rc config.MeshService, w relayWiring, logger *slog.Logger) (relay.AuthConfig, bool, error) {
	if w.admission == nil {
		auth, err := relayAuthConfig(rc)
		return auth, false, err
	}
	auth, err := relayKindAndKey(rc)
	if err != nil {
		return relay.AuthConfig{}, false, err
	}
	auth.Require = true
	if w.org > 0 {
		auth.Meshnet = w.org
	} else {
		// Every organization's devices hold grants from the same coordinator, so
		// without its organization the relay can only check that a device has one.
		logger.Warn("mesh relay: this node's certificate names no organization, so its relay admits any calabi.net device with a valid grant rather than only its own organization's")
	}
	return auth, auth.CoordPub == nil, nil
}

// admittedBy is the posture a node's own relay takes from the platform's answer:
// check grants against key, or — when the platform signs none — admit devices
// without one, since they have none to present.
func admittedBy(base relay.AuthConfig, key ed25519.PublicKey) relay.AuthConfig {
	p := base
	p.CoordPub, p.Require = key, key != nil
	return p
}

// samePosture reports whether two postures admit the same devices. Kind and
// Meshnet never change while a relay runs.
func samePosture(a, b relay.AuthConfig) bool {
	return a.Require == b.Require && bytes.Equal(a.CoordPub, b.CoordPub)
}

// relayAdmissionFirstReminder is how long a relay waits for the platform's
// answer before saying it is still not listening; relayAdmissionReminder how
// often it says so again. Vars so a test need not wait them out.
var (
	relayAdmissionFirstReminder = 30 * time.Second
	relayAdmissionReminder      = 10 * time.Minute
)

// awaitRelayAdmission blocks until a node's own relay knows how to check the
// devices that dial it: the platform's answer to its registration, or, until
// that arrives, the key the previous run heard. ok is false when ctx ended
// first.
//
// It does not listen before then, on purpose. Listening meant admitting whoever
// arrived, which is the hole this closes, and refusing everyone instead would
// hold devices off with backoff (they read a refused grant as a refusal). Not
// listening is the plain signal: the relay is not up yet, and devices use
// another path until it is. On a first start it costs nothing — the relay joins
// its organization's map in the same answer that carries the key.
func awaitRelayAdmission(ctx context.Context, a *relayAdmission, logger *slog.Logger) (ed25519.PublicKey, bool) {
	if heard, key, _ := a.current(); heard {
		return key, true
	}
	if key := a.remembered(); key != nil {
		logger.Info("mesh relay: checking grants with the key kept from the last registration until calabi.net answers this one",
			"coord_pubkey", base64.StdEncoding.EncodeToString(key))
		return key, true
	}
	if why := a.unregistrable(); why != "" {
		logger.Error("mesh relay: not listening: it cannot register with its organization, and registering is how it learns the key its devices' grants are checked against",
			"reason", why)
	} else {
		logger.Info("mesh relay: waiting for calabi.net to answer this relay's registration before listening; the answer carries the key its devices' grants are checked against")
	}
	start := time.Now()
	remind := time.NewTimer(relayAdmissionFirstReminder)
	defer remind.Stop()
	for {
		heard, key, changed := a.current()
		if heard {
			if waited := time.Since(start); waited >= relayAdmissionFirstReminder {
				logger.Info("mesh relay: calabi.net answered; listening", "waited", waited.Round(time.Second))
			}
			return key, true
		}
		select {
		case <-ctx.Done():
			return nil, false
		case <-changed:
		case <-remind.C:
			logger.Warn("mesh relay: still not listening: calabi.net has not answered this relay's registration, and it admits no device before it knows how to check them (see the relay-registrar lines)",
				"waited", time.Since(start).Round(time.Second), "reason", a.unregistrable())
			remind.Reset(relayAdmissionReminder)
		}
	}
}

// followRelayAdmission keeps a node's own relay admitting devices the way the
// platform's latest answer says, for as long as the relay runs: a key where
// there was none, a new key, or none where there was one. Each change replaces
// the hub (relayGens), because a device admitted under the old answer must be
// checked under the new one.
//
// A relay whose config names the key (follow=false) keeps it; the platform's
// answer is then only compared, and a difference said out loud — it means the
// relay is turning its own devices away.
func followRelayAdmission(ctx context.Context, a *relayAdmission, gens *relayGens, start relay.AuthConfig, follow bool, logger *slog.Logger) {
	cur := start
	var reported ed25519.PublicKey
	for {
		heard, key, changed := a.current()
		switch {
		case !heard:
		case follow:
			if next := admittedBy(cur, key); !samePosture(cur, next) {
				logRelayAdmissionChange(logger, cur, next)
				gens.start(next)
				cur = next
			}
		case key != nil && !bytes.Equal(key, cur.CoordPub) && !bytes.Equal(key, reported):
			logger.Error("mesh relay: this node checks grants against the coord_pubkey in its config, but calabi.net signs them with a different key; its devices will be turned away. Remove coord_pubkey from the config and the relay uses the platform's",
				"configured", base64.StdEncoding.EncodeToString(cur.CoordPub), "platform", base64.StdEncoding.EncodeToString(key))
			reported = key
		}
		select {
		case <-ctx.Done():
			return
		case <-changed:
		}
	}
}

// logRelayAdmission says whom a node's own relay admits.
func logRelayAdmission(logger *slog.Logger, auth relay.AuthConfig) {
	if !auth.Require {
		logger.Warn("mesh relay: admitting any device that reaches it: calabi.net returned no key to check grants against (it signs none, or its gateway predates this relay)")
		return
	}
	logger.Info("mesh relay: admitting only its organization's devices, each proving a grant signed by calabi.net",
		"meshnet", auth.Meshnet, "coord_pubkey", base64.StdEncoding.EncodeToString(auth.CoordPub))
}

// logRelayAdmissionChange says what changed, and that the relay's devices are
// about to re-dial.
func logRelayAdmissionChange(logger *slog.Logger, from, to relay.AuthConfig) {
	switch {
	case !to.Require:
		logger.Warn("mesh relay: calabi.net no longer returns a key to check grants against; admitting any device that reaches it from here on (its devices re-dial)")
	case !from.Require:
		logger.Info("mesh relay: calabi.net now returns a key to check grants against; admitting only its organization's devices from here on (the ones admitted without a grant re-dial and prove one)",
			"meshnet", to.Meshnet, "coord_pubkey", base64.StdEncoding.EncodeToString(to.CoordPub))
	default:
		logger.Warn("mesh relay: calabi.net signs grants with a new key; checking against it from here on (its devices re-dial)",
			"was", base64.StdEncoding.EncodeToString(from.CoordPub), "now", base64.StdEncoding.EncodeToString(to.CoordPub))
	}
}

// relayGens runs the relay's hub, and replaces it when the way devices are
// admitted changes — a node's own relay starting to check grants, or checking
// them against a new key.
//
// Replaced, not reconfigured: a pkg/relay hub's posture is fixed when it is
// built, and a link admitted under the old posture must not outlive it. So the
// old hub's connections are closed, from the moment they were accepted rather
// than from when the hub registered them (a connection still in its opening
// frames would otherwise land in the old hub unchecked), and their devices
// re-dial into the new one. Rare by design — every other relay keeps its first
// hub for life.
type relayGens struct {
	ctx    context.Context
	logger *slog.Logger
	rate   *relayRateResolver

	mu  sync.Mutex
	cur *relayGen
	// retired are replaced hubs whose usage has not been drained yet.
	retired []*relay.Hub
}

// relayGen is one hub and every connection handed to it.
type relayGen struct {
	hub    *relay.Hub
	cancel context.CancelFunc

	mu      sync.Mutex
	conns   map[net.Conn]struct{}
	retired bool
}

func newRelayGens(ctx context.Context, logger *slog.Logger, rate *relayRateResolver) *relayGens {
	return &relayGens{ctx: ctx, logger: logger, rate: rate}
}

// start builds a hub for auth, routes new connections to it, and retires the
// one it replaces.
func (s *relayGens) start(auth relay.AuthConfig) {
	hub := relay.NewHub(s.logger, auth)
	// Passing rate.For unconditionally would install a non-nil func value
	// wrapping a nil receiver, so the hub would call it per link instead of
	// skipping the whole path.
	if s.rate != nil {
		hub = hub.WithRateLimiter(s.rate.For)
	}
	gctx, cancel := context.WithCancel(s.ctx)
	go hub.Run(gctx)
	g := &relayGen{hub: hub, cancel: cancel, conns: make(map[net.Conn]struct{})}

	s.mu.Lock()
	old := s.cur
	s.cur = g
	if old != nil {
		s.retired = append(s.retired, old.hub)
	}
	s.mu.Unlock()
	if old != nil {
		old.retire()
	}
}

// serve hands conn to the current hub: a TLS link with the binding of the
// certificate its handshake served, a plaintext one with none.
func (s *relayGens) serve(conn net.Conn, binding *meshproto.DERPBinding) {
	s.mu.Lock()
	g := s.cur
	s.mu.Unlock()
	g.serve(conn, binding)
}

// stop retires the current hub.
func (s *relayGens) stop() {
	s.mu.Lock()
	g := s.cur
	s.mu.Unlock()
	if g != nil {
		g.retire()
	}
}

// takeUsage drains every hub still holding usage: the current one and any
// replaced since the last call. A replaced hub is drained once, after its links
// were closed, which books everything it forwarded.
func (s *relayGens) takeUsage() []relay.UsageDelta {
	s.mu.Lock()
	hubs := s.retired
	s.retired = nil
	if s.cur != nil {
		hubs = append(hubs, s.cur.hub)
	}
	s.mu.Unlock()
	var out []relay.UsageDelta
	for _, h := range hubs {
		out = append(out, h.TakeUsage()...)
	}
	return out
}

func (g *relayGen) serve(conn net.Conn, binding *meshproto.DERPBinding) {
	g.mu.Lock()
	if g.retired {
		g.mu.Unlock()
		_ = conn.Close()
		return
	}
	g.conns[conn] = struct{}{}
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		delete(g.conns, conn)
		g.mu.Unlock()
	}()
	if binding != nil {
		g.hub.ServeBound(conn, *binding)
		return
	}
	g.hub.Serve(conn)
}

// retire closes every connection handed to this hub and stops its grant sweep.
func (g *relayGen) retire() {
	g.mu.Lock()
	if g.retired {
		g.mu.Unlock()
		return
	}
	g.retired = true
	conns := g.conns
	g.conns = make(map[net.Conn]struct{})
	g.mu.Unlock()
	g.cancel()
	for c := range conns {
		_ = c.Close()
	}
}
