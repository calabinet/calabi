package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/calabi/calabi/apps/calabi-edge/internal/config"
	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
	"github.com/calabi/calabi/pkg/relay"
	"github.com/calabi/calabi/pkg/stunserver"
)

// runRelay serves the mesh-relay (calabi-derp) datapath in-process when role is
// "relay" or "both" — the edge/derp merge. It reuses the SAME pkg/relay hub + pkg/stunserver that the standalone
// standalone derp-node binary used to run before it was retired (F2); only the
// assembly differs.
//
// DELIBERATELY ciphertext-only: the hub relays already-encrypted mesh packets by
// node key (pkg/relay never decrypts), and this file imports nothing from the
// edge's TLS-termination path. Isolation is enforced structurally — pkg/relay's
// module graph carries no edge/control-plane code (pkg/relay/deps_test.go) — so
// the tunnel and relay datapaths cannot cross.
//
// reporter (optional; nil in community / when the node has no single org)
// periodically drains the hub and re-sends this node's OWN relay usage as a
// self-<label> region (edge/derp merge). It is wired only for a platform
// node with an org identity.
//
// Blocks until ctx is cancelled, then tears its listeners down.
func runRelay(ctx context.Context, rc config.RelayRole, logger *slog.Logger, reporter *relayUsageReporter) error {
	auth, err := relayAuthConfig(rc)
	if err != nil {
		return err
	}
	logger.Info("relay role: starting mesh-relay datapath",
		"derp_port", rc.RelayDERPPort(), "stun_port", rc.RelaySTUNPort(),
		"kind", auth.Kind, "require_auth", auth.Require, "label", rc.Label,
		"usage_report", reporter != nil)

	hub := relay.NewHub(logger, auth)
	go hub.Run(ctx)
	if reporter != nil {
		go reporter.reportLoop(ctx, hub.TakeUsage)
	}

	// STUN responder (UDP) — best-effort, mirrors calabi-derp. 0 disables it.
	if rc.RelaySTUNPort() > 0 {
		stunAddr := ":" + strconv.Itoa(rc.RelaySTUNPort())
		if ua, uerr := net.ResolveUDPAddr("udp", stunAddr); uerr != nil {
			logger.Warn("relay role: STUN disabled (bad stun_port)", "addr", stunAddr, "err", uerr)
		} else if sc, lerr := net.ListenUDP("udp", ua); lerr != nil {
			logger.Warn("relay role: STUN disabled (bind failed)", "addr", stunAddr, "err", lerr)
		} else {
			logger.Info("relay role: STUN responder listening", "addr", stunAddr)
			go stunserver.Serve(sc, logger)
			go func() { <-ctx.Done(); _ = sc.Close() }()
		}
	}

	// Relay data port (TCP) — the address mesh nodes dial. Ciphertext in and out.
	derpAddr := ":" + strconv.Itoa(rc.RelayDERPPort())
	ln, err := net.Listen("tcp", derpAddr)
	if err != nil {
		return fmt.Errorf("relay listen %s: %w", derpAddr, err)
	}
	logger.Info("relay role: relay listening", "addr", derpAddr)
	go func() { <-ctx.Done(); _ = ln.Close() }()

	for {
		conn, aerr := ln.Accept()
		if aerr != nil {
			if ctx.Err() != nil {
				return nil // clean shutdown
			}
			logger.Warn("relay role: accept error", "err", aerr)
			continue
		}
		go hub.Serve(conn)
	}
}

// relayAuthConfig builds the R0' auth posture from the relay config, mirroring
// the retired calabi-derp's authConfig (its DERP_NODE_KIND / _REQUIRE_AUTH /
// _COORD_PUBKEY are now relay.kind /.require_auth /.coord_pubkey).
// Kind defaults to "self": a merged BYOI node's relay is the org's own relay, and
// defaulting to platform would let it serve traffic an over-quota grant meant to
// stop.
func relayAuthConfig(rc config.RelayRole) (relay.AuthConfig, error) {
	auth := relay.AuthConfig{Require: rc.RequireAuth}
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
	// A relay that requires grants but can't verify one would black-hole every
	// connection. Refuse rather than start silently broken.
	if auth.Require && auth.CoordPub == nil {
		return relay.AuthConfig{}, fmt.Errorf("relay.require_auth is set but relay.coord_pubkey is empty; every connection would be rejected")
	}
	return auth, nil
}
