// Package identity resolves a node's tk_ auth key to the org that owns it, which
// IS the meshnet the node joins. It is one of the two authentication postures a
// coordinator can run (the other is core.StaticAuth over an operator's own key
// file), selected by CALABI_COORD_IDENTITY_ADDR — see prodguard.go, which refuses
// production with neither.
//
// It speaks IdentityHooks, the narrow platform contract in pkg/hooks-proto, NOT
// the control-plane monolith it used to import. That is what lets this file ship
// in the public tree at all: a self-hoster who
// implements four RPCs plugs the coordinator into their own IdP.
package identity

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
	pb "github.com/calabi/calabi/pkg/hooks-proto/hookspb"
)

// RPC is the narrow subset of pb.IdentityHooksClient calabi-coord uses. pb.IdentityHooksClient
// (cluster mode) and bff_edge.BFFEdgeClient both satisfy it, so the same type
// covers direct + gateway wiring later.
type RPC interface {
	ValidateToken(ctx context.Context, in *pb.ValidateTokenRequest, opts ...grpc.CallOption) (*pb.ValidateTokenResponse, error)
}

// Authenticator implements core.Authenticator against identity-svc.
type Authenticator struct {
	logger  *slog.Logger
	client  RPC
	conn    *grpc.ClientConn // nil when constructed via Wrap
	timeout time.Duration
}

// Dial constructs an Authenticator. The connection is lazy (established on the
// first Resolve) so calabi-coord boot doesn't block on identity-svc being up.
func Dial(logger *slog.Logger, addr string) (*Authenticator, error) {
	if addr == "" {
		return nil, fmt.Errorf("identity: empty addr")
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("identity: dial %s: %w", addr, err)
	}
	return &Authenticator{
		logger:  logger.With("component", "identity.authenticator"),
		client:  pb.NewIdentityHooksClient(conn),
		conn:    conn,
		timeout: 3 * time.Second,
	}, nil
}

// Wrap builds an Authenticator from a pre-made client (e.g. a shared bff-edge
// conn). The caller owns the connection; Close is a no-op.
func Wrap(logger *slog.Logger, client RPC) *Authenticator {
	return &Authenticator{logger: logger.With("component", "identity.authenticator"), client: client, timeout: 3 * time.Second}
}

// Close releases the connection when this Authenticator owns one.
func (a *Authenticator) Close() error {
	if a == nil || a.conn == nil {
		return nil
	}
	return a.conn.Close()
}

// Resolve verifies authKey (a tk_ API key) via identity-svc and returns the org
// that owns it as the MeshnetID. It FAILS CLOSED: any RPC error, an invalid
// token, or a token with no resolvable org all deny (unlike the edge's
// data-plane verifier, which fails open — enrolling a node into a private mesh
// warrants the stricter posture).
func (a *Authenticator) Resolve(ctx context.Context, authKey string) (core.Identity, error) {
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()

	resp, err := a.client.ValidateToken(ctx, &pb.ValidateTokenRequest{AccessToken: authKey})
	if err != nil {
		a.logger.Warn("identity validate failed; denying", "err", err)
		return core.Identity{}, fmt.Errorf("identity validate: %w", err)
	}
	if !resp.GetValid() {
		return core.Identity{}, core.ErrAuthDenied
	}
	org := orgFromRoles(resp.GetRoles())
	if org == 0 {
		a.logger.Warn("valid token but no org role; denying", "user_id", resp.GetUserId())
		return core.Identity{}, core.ErrAuthDenied
	}
	// Platform node tags (tag:server etc.) are assigned in the console and land
	// with the DB-backed node store in MESH.8; a tk_ key carries none today.
	// Attribution: an api-key carries "actor:<id>" (the person who minted it);
	// a login token is the person itself. Mirrors how tunnels attribute an agent
	// device to a real account rather than to the key.
	owner := actorFromRoles(resp.GetRoles())
	if owner == 0 {
		owner = resp.GetUserId()
	}
	return core.Identity{Meshnet: core.MeshnetID(org), UserID: owner}, nil
}

// orgFromRoles parses identity-svc's role strings ("org:42 ws:7 scopes:...") and
// returns the org id, or 0 if absent. Mirrors calabi-edge's identity client.
// actorFromRoles pulls "actor:<id>" (the human who minted an api-key) out of
// identity-svc's role strings. 0 when absent.
func actorFromRoles(roles []string) int64 {
	for _, r := range roles {
		for _, kv := range strings.Fields(r) {
			if v, ok := strings.CutPrefix(kv, "actor:"); ok {
				if id, err := strconv.ParseInt(v, 10, 64); err == nil {
					return id
				}
			}
		}
	}
	return 0
}

func orgFromRoles(roles []string) int64 {
	for _, r := range roles {
		for _, kv := range strings.Fields(r) {
			if v, ok := strings.CutPrefix(kv, "org:"); ok {
				if id, err := strconv.ParseInt(v, 10, 64); err == nil {
					return id
				}
			}
		}
	}
	return 0
}
