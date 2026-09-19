package core

import (
	"context"
	"crypto/ed25519"
)

// Edges a self-hosted coordinator's nodes serve tunnels through.
//
// On a self-hosted server the coordinator is the one identity a device has. The
// edge accepts the grant this coordinator signs — the relay grant, because one
// calabi-edge is both a relay and a tunnel edge and both halves check the same
// signature — and the device learns from the coordinator where the edge is and
// which certificate it presents. That pin comes from a server the device has
// already pinned, so the device never has to confirm the edge's certificate
// itself.

// Edge is one edge as a node dials it.
type Edge struct {
	// Addr is host:port of the edge's control listener, as devices reach it.
	Addr string
	// Pin is meshproto.CertPin of the certificate the edge presents. Empty means
	// the certificate is checked against the system's roots and the host name.
	Pin string
}

// EdgeDirectory lists the edges. Its answer may change at any time — an edge
// presenting a new certificate — so nodes ask again periodically and whenever
// an edge turns them away.
type EdgeDirectory interface {
	Edges() []Edge
}

// EdgeAccess returns the edges node may serve tunnels through and the grant it
// presents to them. The grant is nil when this coordinator signs none; edges
// then have no way to accept the node, and the caller says so.
func (c *Coordinator) EdgeAccess(ctx context.Context, node *Node) ([]Edge, []byte) {
	var edges []Edge
	if c.Edges != nil {
		edges = c.Edges.Edges()
	}
	return edges, c.relayGrantFor(ctx, node)
}

// PublicKey is the half of the signing key edges and relays are configured
// with.
func (s *SigningRelayGrantIssuer) PublicKey() ed25519.PublicKey {
	if len(s.Key) != ed25519.PrivateKeySize {
		return nil
	}
	return s.Key.Public().(ed25519.PublicKey)
}
