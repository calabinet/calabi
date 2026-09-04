// Package tunnelstore is the calabi-edge-side gRPC client to tunnel-svc.
//
// It exposes a tiny interface tied to the edge's NEW_PROXY / CLOSE_PROXY
// life-cycle: persist on creation, mark offline on close. All calls are
// best-effort -- if tunnel-svc is unreachable the edge still routes
// traffic locally; we'd rather serve customers than refuse on a control-
// plane blip.
package tunnelstore

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/calabi/calabi/pkg/edge-proto/edgepb"
)

// ErrTunnelDisabled signals that tunnel-svc refused a Claim because the row
// was disabled by an admin (gRPC PermissionDenied). The NEW_PROXY handler
// MUST hard-fail on this — it must NOT fall back to Persist, or it would
// resurrect an admin-blocked tunnel under a brand-new id. See.
var ErrTunnelDisabled = errors.New("tunnelstore: tunnel disabled by admin")

// ErrClaimConflict signals that tunnel-svc rejected a Claim as a genuine
// ownership conflict (gRPC FailedPrecondition): the row is owned by another
// live edge and the re-home wasn't authorized (different region, different
// client, or a still-alive previous owner). Like ErrTunnelDisabled, the
// NEW_PROXY handler MUST hard-fail on this — it must NOT fall back to Persist.
// Falling back would mint a brand-new duplicate row AND orphan-delete the
// conflicting one, which is exactly how the edge produced bursts of
// identical deleted TCP rows whenever a port tunnel bounced between same-region
// edges (TCP carries no domain, so's intra-region re-home didn't cover
// it until tunnel-svc learned to match on base_domain). With that fix in place
// a legitimate same-client same-region re-home now SUCCEEDS at tunnel-svc, so a
// FailedPrecondition here is a real conflict that should surface, not churn.
var ErrClaimConflict = errors.New("tunnelstore: claim conflict (owned by another edge)")

// managedSubdomainSeqRE matches the SubdomainAllocator's output shape
// ("uNNNNNN.<base>"). The captured digits feed allocator.Seed so the
// next allocation lands above any existing row.
var managedSubdomainSeqRE = regexp.MustCompile(`^u(\d+)\.`)

// RPC is the narrow subset of pb.TunnelControlClient the edge actually
// uses. bff_edge.BFFEdgeClient satisfies it directly because the
// 7 method names + signatures match — bff-edge proxies them unchanged.
type RPC interface {
	CreateTunnel(ctx context.Context, in *pb.CreateTunnelRequest, opts ...grpc.CallOption) (*pb.Tunnel, error)
	ClaimTunnel(ctx context.Context, in *pb.ClaimTunnelRequest, opts ...grpc.CallOption) (*pb.Tunnel, error)
	ReportStatus(ctx context.Context, in *pb.ReportStatusRequest, opts ...grpc.CallOption) (*pb.ReportStatusResponse, error)
	ListTunnels(ctx context.Context, in *pb.ListTunnelsRequest, opts ...grpc.CallOption) (*pb.ListTunnelsResponse, error)
	ListEdgeClaimedPorts(ctx context.Context, in *pb.ListEdgeClaimedPortsRequest, opts ...grpc.CallOption) (*pb.ListEdgeClaimedPortsResponse, error)
	DeleteTunnel(ctx context.Context, in *pb.DeleteTunnelRequest, opts ...grpc.CallOption) (*pb.DeleteTunnelResponse, error)
	Resolve(ctx context.Context, in *pb.ResolveRequest, opts ...grpc.CallOption) (*pb.ResolveResponse, error)
}

// Client wraps a tunnel-svc gRPC client.
type Client struct {
	addr       string
	logger     *slog.Logger
	conn       *grpc.ClientConn // nil when constructed via Wrap
	rpc        RPC
	timeout    time.Duration
	edgeNodeID int64
	edgeLabel  string
	// baseDomain is the edge's local HTTPListener.BaseDomain.
	// Plumbed into Persist + Claim so tunnel-svc's zone-edge check can
	// reject a misconfigured cross-edge claim before it lands. Empty
	// disables the cross-check on the server side.
	baseDomain string
}

// The direct-dial constructor was removed in F3 step 2b: every edge now
// reaches the control plane through bff-edge, so this package is only ever
// handed a ready client.
// Wrap constructs a Client from a pre-made RPC client. The caller owns
// the gRPC connection (typically a shared bff-edge conn) so Close() is
// a no-op.
func Wrap(logger *slog.Logger, client RPC, edgeNodeID int64, nodeLabel, baseDomain string) *Client {
	if edgeNodeID == 0 {
		edgeNodeID = hashToID(nodeLabel)
	}
	return &Client{
		logger:     logger.With("component", "tunnelstore"),
		rpc:        client,
		timeout:    3 * time.Second,
		edgeNodeID: edgeNodeID,
		edgeLabel:  nodeLabel,
		baseDomain: strings.ToLower(strings.TrimSpace(baseDomain)),
	}
}

// Close releases the underlying gRPC connection when this Client owns
// one. No-op for Wrap()ped instances.
func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// EdgeNodeID returns the numeric id this edge identifies as in tunnel-svc.
func (c *Client) EdgeNodeID() int64 { return c.edgeNodeID }

// PersistInput is the shape we mint a row from on a successful NEW_PROXY.
type PersistInput struct {
	OrgID       int64
	WorkspaceID int64
	ClientID    int64
	Name        string
	Type        string // http/https/tcp/udp/sni
	LocalAddr   string
	Domain      string
	RemotePort  int32
}

// PersistResult captures the row id tunnel-svc assigned so we can later
// call ReportStatus / DeleteTunnel without re-resolving.
type PersistResult struct {
	TunnelID int64
	// ConfigJSON is the tunnel row's server-authoritative config blob
	// (security policy: IP allowlist, basic-auth, …). The edge parses it
	// into a per-proxy policy and enforces it in the data plane — it is
	// NOT taken from the daemon's NEW_PROXY options, so a tampered client
	// cannot drop its own restrictions. Empty for CLI-created rows that
	// carry no server-side policy. See apps/calabi-edge/internal/policy.
	ConfigJSON string
}

// Persist creates a tunnel row in tunnel-svc. Returns a partial result
// even on AlreadyExists (re-using an existing row keyed by domain/port).
//
// Errors that aren't AlreadyExists / Unavailable are surfaced to the
// caller; the edge then decides whether to refuse the registration.
func (c *Client) Persist(ctx context.Context, in PersistInput) (PersistResult, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	t, err := c.rpc.CreateTunnel(ctx, &pb.CreateTunnelRequest{
		OrgId:       in.OrgID,
		WorkspaceId: in.WorkspaceID,
		ClientId:    in.ClientID,
		Name:        in.Name,
		Type:        in.Type,
		LocalAddr:   in.LocalAddr,
		Domain:      strings.ToLower(strings.TrimSpace(in.Domain)),
		RemotePort:  in.RemotePort,
		// stamp the row with THIS edge's id so tunnel-svc's
		// (edge_node_id, remote_port) unique check actually fires. Before
		// this, Persist sent edge_node_id=0 and the unique check short-
		// circuited — leaving room for a ghost row at the same port. With
		// it set, two Persists racing for the same port get one success
		// and one AlreadyExists (caller handles).
		EdgeNodeId: c.edgeNodeID,
		// declare THIS edge's local base_domain so tunnel-svc can
		// reject mismatched zone↔edge cross-claims in the per-edge
		// wildcard DNS mode.
		BaseDomain: c.baseDomain,
	})
	if err == nil {
		return PersistResult{TunnelID: t.GetMeta().GetId(), ConfigJSON: t.GetConfigJson()}, nil
	}
	// On AlreadyExists, look up by the same key so we can still report
	// status / delete later. This makes Persist idempotent w.r.t. edge
	// reconnects that re-create the same domain.
	if status.Code(err) == codes.AlreadyExists {
		resolved, rerr := c.resolveCurrent(ctx, in)
		if rerr == nil {
			return PersistResult{TunnelID: resolved.GetMeta().GetId(), ConfigJSON: resolved.GetConfigJson()}, nil
		}
		c.logger.Warn("persist already_exists but resolve failed",
			"err", err, "resolve_err", rerr)
	}
	return PersistResult{}, err
}

// ClaimInput is the per-tunnel patch shape used by Claim. Mirrors the
// fields the edge knows after a successful NEW_PROXY → registrar.Register*
// round-trip: which row in tunnel-svc, which edge is claiming, and the
// runtime values (domain / port) the edge just allocated.
type ClaimInput struct {
	TunnelID      int64
	OrgID         int64
	ClientID      int64 // 0 = unknown
	EdgeNodeLabel string
	Domain        string
	RemotePort    int32
}

// Claim writes the edge-side runtime fields onto a pending tunnel row
// that the console pre-created with edge_node_id=0. Used by the daemon-
// mode auto-claim path: client receives CONFIG_PUSH.UpsertProxies with
// the row id, sends NEW_PROXY with claim_tunnel_id=id, and the edge
// follows up by telling tunnel-svc "I'm taking this one".
//
// Returns the same TunnelID on success — the caller stamps it onto the
// in-memory Proxy so OnProxyClosed can later ReportStatus correctly.
//
// Errors:
//   - codes.NotFound          : row was deleted between push and claim.
//   - codes.FailedPrecondition: another edge already claimed it, or the
//     row's org/client_id mismatches. Caller
//     should fall back to creating a fresh row
//     via Persist (less ideal but recoverable).
//   - other                   : transport / internal — surfaced to caller.
func (c *Client) Claim(ctx context.Context, in ClaimInput) (PersistResult, error) {
	if in.TunnelID == 0 {
		return PersistResult{}, fmt.Errorf("tunnelstore: claim: tunnel_id required")
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	t, err := c.rpc.ClaimTunnel(ctx, &pb.ClaimTunnelRequest{
		Id:            in.TunnelID,
		OrgId:         in.OrgID,
		ClientId:      in.ClientID,
		EdgeNodeId:    c.edgeNodeID,
		EdgeNodeLabel: in.EdgeNodeLabel,
		Domain:        strings.ToLower(strings.TrimSpace(in.Domain)),
		RemotePort:    in.RemotePort,
		// zone-edge consistency proof — see Persist.
		BaseDomain: c.baseDomain,
	})
	if err != nil {
		// PermissionDenied ⇒ admin-disabled. Return a typed sentinel
		// so OnProxyOpened hard-fails the NEW_PROXY (no Persist fallback) —
		// resurrecting the tunnel under a fresh row would defeat the disable.
		if status.Code(err) == codes.PermissionDenied {
			return PersistResult{}, fmt.Errorf("%w: %v", ErrTunnelDisabled, err)
		}
		// FailedPrecondition ⇒ a genuine ownership conflict (different
		// region/client, or a still-alive previous owner). Return a typed
		// sentinel so OnProxyOpened hard-fails instead of falling back to
		// Persist+orphan-delete (which minted duplicate TCP rows). NotFound and
		// transport errors keep the old behavior (return raw err) so the
		// "pending row vanished between push and claim" case still re-creates.
		if status.Code(err) == codes.FailedPrecondition {
			return PersistResult{}, fmt.Errorf("%w: %v", ErrClaimConflict, err)
		}
		return PersistResult{}, err
	}
	return PersistResult{TunnelID: t.GetMeta().GetId(), ConfigJSON: t.GetConfigJson()}, nil
}

// ReportStatus updates a tunnel's status + reason. Best-effort.
func (c *Client) ReportStatus(ctx context.Context, tunnelID int64, statusStr, reason string) {
	if tunnelID == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	_, err := c.rpc.ReportStatus(ctx, &pb.ReportStatusRequest{
		TunnelId: tunnelID,
		Status:   statusStr,
		Reason:   reason,
	})
	if err != nil {
		c.logger.Warn("report status failed", "id", tunnelID, "err", err)
	}
}

// ListByClient returns all live tunnels owned by clientID under orgID.
// Used by the Phase C catch-up flow: when a client (re)connects, the
// edge pulls its tunnel set from tunnel-svc and pushes them down via
// CONFIG_PUSH so console-created entries land on the client immediately.
//
// Best-effort: a transport failure returns the error; the caller is
// expected to log + skip the catch-up rather than fail the connect.
// Filtering is done client-side because tunnel-svc.ListTunnelsRequest
// has no client_id field yet (would be cheap to add later).
func (c *Client) ListByClient(ctx context.Context, orgID, clientID int64) ([]*pb.Tunnel, error) {
	if orgID <= 0 || clientID <= 0 {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, err := c.rpc.ListTunnels(ctx, &pb.ListTunnelsRequest{
		OrgId: orgID,
		Page:  &pb.PageRequest{PageSize: 200},
	})
	if err != nil {
		return nil, err
	}
	out := make([]*pb.Tunnel, 0, 4)
	for _, t := range resp.GetItems() {
		if t.GetClientId() != clientID {
			continue
		}
		//: never re-push a disabled tunnel to the daemon —
		// admin-disabled (disabled_by_admin) or user-disabled
		// (status=disabled). The authoritative gate is ClaimTunnel (which
		// refuses it), but skipping it here keeps the daemon from attempting
		// a doomed NEW_PROXY and spamming claim-refused logs on reconnect.
		if t.GetDisabledByAdmin() || t.GetStatus() == "disabled" {
			continue
		}
		out = append(out, t)
	}
	return out, nil
}

// ListEdgeClaimedPorts returns the set of remote_port values
// currently claimed by live tunnel rows owned by this edge. Called once
// at edge boot so the in-memory PortPool can Reserve() each port,
// preventing it from re-issuing a port that another member's tunnel
// already holds in DB. Best-effort: a transport failure returns the
// error and the caller should log + carry on (the pool starts cold,
// reverting to behaviour for that boot).
func (c *Client) ListEdgeClaimedPorts(ctx context.Context) ([]int32, error) {
	if c.edgeNodeID == 0 {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, err := c.rpc.ListEdgeClaimedPorts(ctx, &pb.ListEdgeClaimedPortsRequest{
		EdgeNodeId: c.edgeNodeID,
	})
	if err != nil {
		return nil, err
	}
	return resp.GetPorts(), nil
}

// OwnerEntry is one host→owning-edge mapping returned by ResolveOwners.
type OwnerEntry struct {
	Domain     string
	EdgeNodeID int64
}

// resolveOwnersRPC is the optional capability the underlying gRPC client
// must expose for ResolveOwners to work. BOTH pb.TunnelControlClient
// (cluster mode) AND bff_edge.BFFEdgeClient (bff-edge mode, since
// 2026-06-03) satisfy it — bff-edge now proxies ResolveOwners verbatim,
// so same-region mesh works in both modes. The type assertion +
// ErrResolveOwnersUnsupported fallback is kept as a guard for any future
// transport that doesn't implement the method.
type resolveOwnersRPC interface {
	ResolveOwners(ctx context.Context, in *pb.ResolveOwnersRequest, opts ...grpc.CallOption) (*pb.ResolveOwnersResponse, error)
}

// ErrResolveOwnersUnsupported is returned when the underlying transport
// can't issue ResolveOwners. With bff-edge now proxying it, this only
// fires for a transport that lacks the method; callers treat it as "mesh
// owner discovery unavailable" and keep serving without peer forwarding.
var ErrResolveOwnersUnsupported = fmt.Errorf("tunnelstore: ResolveOwners not supported by this transport")

// ResolveOwners returns the host→owning-edge map for every enabled
// HTTP/HTTPS/SNI tunnel under baseDomain. Same-region edges
// share a base_domain, so this yields the whole region's owner registry in
// one call. Read-only; safe to poll on an interval.
//
// Conditional poll (ETag-style): pass the generation token returned by the
// previous successful call as knownGen (empty on the first poll). When the
// server's current generation still equals knownGen, it replies unchanged=true
// with no items — owners is then nil and the caller keeps its existing cache.
// gen is the server's current generation; feed it back as knownGen next poll.
func (c *Client) ResolveOwners(ctx context.Context, baseDomain, knownGen string) (owners []OwnerEntry, gen string, unchanged bool, err error) {
	base := strings.ToLower(strings.TrimSpace(baseDomain))
	if base == "" {
		return nil, "", false, nil
	}
	rr, ok := c.rpc.(resolveOwnersRPC)
	if !ok {
		return nil, "", false, ErrResolveOwnersUnsupported
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, err := rr.ResolveOwners(ctx, &pb.ResolveOwnersRequest{
		BaseDomain:      base,
		KnownGeneration: knownGen,
	})
	if err != nil {
		return nil, "", false, err
	}
	if resp.GetUnchanged() {
		return nil, resp.GetGeneration(), true, nil
	}
	out := make([]OwnerEntry, 0, len(resp.GetItems()))
	for _, it := range resp.GetItems() {
		if d := it.GetDomain(); d != "" && it.GetEdgeNodeId() != 0 {
			out = append(out, OwnerEntry{Domain: d, EdgeNodeID: it.GetEdgeNodeId()})
		}
	}
	return out, resp.GetGeneration(), false, nil
}

// MaxManagedSubdomainSeq scans tunnels under orgID and returns the highest
// N where some row's domain matches "u<N>.<base>". 0 if none. Used by the
// edge at boot to seed the SubdomainAllocator above any already-claimed
// subdomain so the next Allocate() doesn't collide with a row already in
// tunnel-svc (which would cause CodeProxyDuplicate / FailedPrecondition).
//
// Best-effort: transport / NotFound returns (0, err) — the caller logs
// and falls back to the file-backed seq.
//
// TODO(multi-org): dev assumes a single org=1. Multi-tenant edges will
// need to iterate every org served. A cheaper alternative is adding a
// dedicated tunnel-svc RPC that returns the per-base max in one round-
// trip, but that's a proto change we don't need yet.
func (c *Client) MaxManagedSubdomainSeq(ctx context.Context, base string, orgID int64) (uint64, error) {
	if orgID <= 0 || strings.TrimSpace(base) == "" {
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, err := c.rpc.ListTunnels(ctx, &pb.ListTunnelsRequest{
		OrgId: orgID,
		Page:  &pb.PageRequest{PageSize: 500},
	})
	if err != nil {
		return 0, err
	}
	wantSuffix := "." + strings.ToLower(strings.TrimSpace(base))
	var max uint64
	for _, t := range resp.GetItems() {
		d := strings.ToLower(t.GetDomain())
		if !strings.HasSuffix(d, wantSuffix) {
			continue
		}
		m := managedSubdomainSeqRE.FindStringSubmatch(d)
		if len(m) != 2 {
			continue
		}
		n, perr := strconv.ParseUint(m[1], 10, 64)
		if perr != nil {
			continue
		}
		if n > max {
			max = n
		}
	}
	return max, nil
}

// Delete soft-deletes a tunnel row. Best-effort; idempotent.
func (c *Client) Delete(ctx context.Context, tunnelID int64) {
	if tunnelID == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	_, err := c.rpc.DeleteTunnel(ctx, &pb.DeleteTunnelRequest{Id: tunnelID})
	if err != nil {
		c.logger.Warn("delete tunnel failed", "id", tunnelID, "err", err)
	}
}

func (c *Client) resolveCurrent(ctx context.Context, in PersistInput) (*pb.Tunnel, error) {
	switch strings.ToLower(in.Type) {
	case "http", "https", "sni":
		resp, err := c.rpc.Resolve(ctx, &pb.ResolveRequest{Domain: in.Domain})
		if err != nil {
			return nil, err
		}
		if !resp.GetFound() {
			return nil, fmt.Errorf("not found")
		}
		return resp.GetTunnel(), nil
	case "tcp", "udp":
		resp, err := c.rpc.Resolve(ctx, &pb.ResolveRequest{
			EdgeNodeId: c.edgeNodeID,
			RemotePort: in.RemotePort,
		})
		if err != nil {
			return nil, err
		}
		if !resp.GetFound() {
			return nil, fmt.Errorf("not found")
		}
		return resp.GetTunnel(), nil
	default:
		return nil, fmt.Errorf("unknown type %q", in.Type)
	}
}

// hashToID maps a node-label string to a stable int64 id by FNV-1a.
// Used when config.tunnel.edge_node_id is left zero. Avoids requiring
// edges to know their assigned numeric id ahead of time.
func hashToID(label string) int64 {
	if label == "" {
		return 1
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(label))
	v := int64(h.Sum64() & 0x7fffffffffffffff)
	if v == 0 {
		// Pathological case; coerce so 0 stays sentinel.
		v = 1
	}
	return v
}

// ParseTenant turns the role strings identity-svc emits ("org:42 ws:7")
// back into int64 org+workspace ids for tunnel-svc writes. Free helper
// for callers that have a verifier result on hand.
func ParseTenant(orgStr, wsStr string) (orgID, wsID int64) {
	orgID, _ = strconv.ParseInt(orgStr, 10, 64)
	wsID, _ = strconv.ParseInt(wsStr, 10, 64)
	if orgID == 0 {
		orgID = 1 // pre-tenant-svc: everyone lives under org_id=1
	}
	if wsID == 0 {
		wsID = 1
	}
	return orgID, wsID
}
