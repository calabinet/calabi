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
	// Scope gate (audit finding MESH-3). Joining a mesh is a WRITE: the node
	// gets an address, the full netmap (every device's name, overlay, public
	// endpoints, subnet routes) and, under a permissive policy, reach to every
	// peer. Before this, coord looked only at which org a credential named, so a
	// key handed to a monitoring script for reading — or one minted with no
	// scopes at all — was a network credential.
	//
	// user_id == 0 is identity-svc's api-key discriminator (the same one the
	// BFFs gate on). A human session carries a real user id and scopes like
	// "org.role.developer", which are not ".write" — so the rule applies ONLY to
	// machine credentials, and logging a daemon in interactively still works.
	//
	// The write-capable test mirrors bff-console's writeCapableScope, the rule
	// that decides who may MINT such a key (audit 1-B): one place decides what
	// "write credential" means.
	if resp.GetUserId() == 0 && !hasWriteScope(resp.GetRoles()) {
		a.logger.Warn("mesh enrollment denied: api key carries no write scope",
			"org", org, "actor", owner, "scopes", scopesFromRoles(resp.GetRoles()))
		return core.Identity{}, core.ErrAuthDenied
	}
	return core.Identity{Meshnet: core.MeshnetID(org), UserID: owner, Principal: principalFor(resp)}, nil
}

// principalFor names what a validated credential is, in the form Reauthorize
// takes back: the person for a login token, the key for an API key. identity-svc
// puts an API key's id in its roles as "apikey:<id>"; one that predates that
// yields "", and a node enrolled with it has to present its credential again
// rather than come back by proof alone.
func principalFor(resp *pb.ValidateTokenResponse) string {
	if uid := resp.GetUserId(); uid > 0 {
		return "user:" + strconv.FormatInt(uid, 10)
	}
	if id := idFromRoles(resp.GetRoles(), "apikey:"); id > 0 {
		return "apikey:" + strconv.FormatInt(id, 10)
	}
	return ""
}

// Spend has nothing to count: a platform credential is a login or an API key,
// not a key with a number of uses.
func (a *Authenticator) Spend(context.Context, string) (func(), error) { return func() {}, nil }

// enrollmentChecker is the call Reauthorize makes. Separate from RPC so a client
// that only validates tokens (a test fake, an older contract) still builds, and
// is refused at Reauthorize rather than trusted.
type enrollmentChecker interface {
	CheckEnrollment(ctx context.Context, in *pb.CheckEnrollmentRequest, opts ...grpc.CallOption) (*pb.CheckEnrollmentResponse, error)
}

// Reauthorize asks identity-svc whether the principal a node enrolled as still
// admits it to the org — the check a login token or an API key used to get on
// every reconnect, now that an enrolled node can come back without presenting
// one. Fails closed, like
// Resolve: an error or an unknown principal refuses, and the node falls back to
// enrolling with its credential.
func (a *Authenticator) Reauthorize(ctx context.Context, meshnet core.MeshnetID, principal string) error {
	kind, idText, _ := strings.Cut(principal, ":")
	id, err := strconv.ParseInt(idText, 10, 64)
	if err != nil || id <= 0 {
		return core.ErrAuthDenied
	}
	req := &pb.CheckEnrollmentRequest{OrgId: int64(meshnet)}
	switch kind {
	case "user":
		req.UserId = id
	case "apikey":
		req.ApiKeyId = id
	default:
		return core.ErrAuthDenied
	}
	checker, ok := a.client.(enrollmentChecker)
	if !ok {
		return fmt.Errorf("identity: this client cannot re-check an enrollment")
	}
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	resp, err := checker.CheckEnrollment(ctx, req)
	if err != nil {
		a.logger.Warn("identity enrollment check failed; refusing re-registration", "org", meshnet, "principal", principal, "err", err)
		return fmt.Errorf("identity check enrollment: %w", err)
	}
	if !resp.GetValid() {
		a.logger.Info("re-registration refused: enrollment no longer valid", "org", meshnet, "principal", principal, "reason", resp.GetReason())
		return core.ErrAuthDenied
	}
	return nil
}

// scopesFromRoles pulls the "scopes:a,b" element out of identity-svc's role
// strings ("org:42 ws:7 scopes:tunnel.read,tunnel.write"). nil when absent.
func scopesFromRoles(roles []string) []string {
	for _, r := range roles {
		for _, kv := range strings.Fields(r) {
			if v, ok := strings.CutPrefix(kv, "scopes:"); ok {
				return strings.Split(v, ",")
			}
		}
	}
	return nil
}

// hasWriteScope reports whether the credential carries any write-capable scope.
func hasWriteScope(roles []string) bool {
	for _, s := range scopesFromRoles(roles) {
		s = strings.TrimSpace(s)
		if s == "tunnel.write" || strings.HasSuffix(s, ".write") {
			return true
		}
	}
	return false
}

// orgFromRoles parses identity-svc's role strings ("org:42 ws:7 scopes:...") and
// returns the org id, or 0 if absent. Mirrors calabi-edge's identity client.
// actorFromRoles pulls "actor:<id>" (the human who minted an api-key) out of
// identity-svc's role strings. 0 when absent.
func actorFromRoles(roles []string) int64 { return idFromRoles(roles, "actor:") }

// idFromRoles pulls the first "<prefix><id>" element out of identity-svc's role
// strings. 0 when absent.
func idFromRoles(roles []string, prefix string) int64 {
	for _, r := range roles {
		for _, kv := range strings.Fields(r) {
			if v, ok := strings.CutPrefix(kv, prefix); ok {
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
