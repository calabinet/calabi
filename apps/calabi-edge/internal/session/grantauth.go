package session

import (
	"context"
	"fmt"
	"strconv"
	"time"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	proto "github.com/calabinet/calabi/pkg/protocol"
)

// Grant authentication — how a self-hosted edge accepts a device.
//
// The device's coordinator is the one identity it has. The edge holds that
// coordinator's public key and checks two things, both offline:
//
//   - the grant: the coordinator's signed statement that a node key belongs to
//     one of its meshnets, valid until a time — the same grant the relay half
//     of this program checks;
//   - the proof: the device answering this connection's challenge
//     (HELLO_ACK.auth_challenge) with that node key's private half, which is
//     what makes a grant anyone could have seen useless to anyone but its node.
//
// The grant lasts an hour. The device sends a renewed one (AUTH_REFRESH) before
// it runs out; a session whose grant expires unrenewed is ended, which is how a
// device deleted, disabled or signed out on the coordinator loses its tunnels.

// GrantAuth checks grants against the coordinator this edge belongs to.
type GrantAuth interface {
	// VerifyGrant checks the grant's signature and that it is valid at now and
	// good for this edge, and returns what it says.
	VerifyGrant(grant []byte, now time.Time) (meshproto.RelayGrant, error)
}

// authenticateGrant accepts auth by its grant and proof, and records on the
// session what the grant said.
func (s *Session) authenticateGrant(grants GrantAuth, ch meshproto.EdgeChallenge, ephPriv [meshproto.KeyLen]byte, auth *proto.AuthRequest) (tenantID, workspaceID, clientID string, err error) {
	if len(auth.Grant) == 0 {
		return "", "", "", fmt.Errorf("no grant: this edge accepts devices of its coordinator only")
	}
	g, err := grants.VerifyGrant(auth.Grant, time.Now())
	if err != nil {
		return "", "", "", err
	}
	if err := meshproto.OpenEdgeProof(ch, ephPriv, g.Node, auth.Proof); err != nil {
		return "", "", "", err
	}
	s.mu.Lock()
	s.grants, s.grantNode, s.grantExpiry = grants, g.Node, g.Expiry
	s.mu.Unlock()
	return strconv.FormatInt(g.Meshnet, 10), "default", g.Node.String(), nil
}

// handleAuthRefresh takes a renewed grant. It must be for the node this
// session proved; anything else ends the session.
func (s *Session) handleAuthRefresh(f proto.Frame) {
	s.mu.Lock()
	grants, node := s.grants, s.grantNode
	s.mu.Unlock()
	if grants == nil {
		s.logger.Debug("AUTH_REFRESH on a session that did not authenticate by grant; ignored")
		return
	}
	var req proto.AuthRefresh
	if err := proto.Unmarshal(f.Payload, &req); err != nil {
		s.endForGrant("calabi.err.auth.invalid_grant", "malformed AUTH_REFRESH: "+err.Error())
		return
	}
	g, err := grants.VerifyGrant(req.Grant, time.Now())
	switch {
	case err != nil:
		s.endForGrant("calabi.err.auth.invalid_grant", "renewed grant refused: "+err.Error())
	case g.Node != node:
		s.endForGrant("calabi.err.auth.invalid_grant", "renewed grant is for another device")
	default:
		s.mu.Lock()
		if g.Expiry.After(s.grantExpiry) {
			s.grantExpiry = g.Expiry
		}
		s.mu.Unlock()
	}
}

// watchGrantExpiry ends the session when its grant runs out without a renewal.
// A no-op for a session that did not authenticate by grant.
func (s *Session) watchGrantExpiry(ctx context.Context) {
	for {
		s.mu.Lock()
		grants, exp := s.grants, s.grantExpiry
		s.mu.Unlock()
		if grants == nil {
			return
		}
		wait := time.Until(exp)
		if wait <= 0 {
			s.endForGrant("calabi.err.auth.grant_expired", "the device's grant expired and was not renewed")
			return
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-s.closedCh:
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// endForGrant tells the device why, and ends the session.
func (s *Session) endForGrant(key, why string) {
	s.logger.Info("ending session: its grant is no longer good", "reason", why, "client_id", s.ClientID)
	_ = s.sendError(proto.CodeAuthInvalidToken, key, why)
	_ = s.Close()
}
