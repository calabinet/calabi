// Package identity is the calabi-edge-side client to identity-svc.
//
// It wraps the gRPC ValidateToken RPC behind the session.TokenVerifier
// interface, so the control listener stays oblivious to whether tokens
// come from static YAML or the real control plane.
//
// Fallback policy: if the gRPC call fails (network error, identity-svc
// down), we return "unknown token" rather than crashing the edge -- a
// known-bad token at worst lets a connection in that the listener can
// drop later when proxying actually happens.
package identity

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc"

	pb "github.com/calabi/calabi/pkg/edge-proto/edgepb"
)

// RPC is the narrow subset of pb.IdentityClient the edge actually uses.
// Both pb.IdentityClient and bff_edge.BFFEdgeClient satisfy it
// directly because the method names + signatures match — bff-edge
// proxies these 4 RPCs unchanged from the wire shape, so a single
// interface covers cluster-mode + bff-edge-mode without an adapter.
type RPC interface {
	ValidateToken(ctx context.Context, in *pb.ValidateTokenRequest, opts ...grpc.CallOption) (*pb.ValidateTokenResponse, error)
	RegisterEdgeNode(ctx context.Context, in *pb.RegisterEdgeNodeRequest, opts ...grpc.CallOption) (*pb.RegisterEdgeNodeResponse, error)
	ReportClientPresence(ctx context.Context, in *pb.ReportClientPresenceRequest, opts ...grpc.CallOption) (*pb.ReportClientPresenceResponse, error)
	GetOrgOnlineCount(ctx context.Context, in *pb.GetOrgOnlineCountRequest, opts ...grpc.CallOption) (*pb.GetOrgOnlineCountResponse, error)
}

// Verifier implements session.TokenVerifier against an identity-svc
// gRPC endpoint. The same instance is safe to share across goroutines.
type Verifier struct {
	addr    string
	logger  *slog.Logger
	client  RPC
	conn    *grpc.ClientConn // nil when constructed via Wrap (shared conn owned elsewhere)
	timeout time.Duration
}

// The direct-dial constructor was removed in F3 step 2b: every edge now
// reaches the control plane through bff-edge, so this package is only ever
// handed a ready client.
// Wrap constructs a Verifier from a pre-made gRPC client (e.g. a
// shared bff-edge connection). The connection is owned by the caller;
// Close() on a wrapped Verifier is a no-op.
func Wrap(logger *slog.Logger, client RPC) *Verifier {
	return &Verifier{
		logger:  logger.With("component", "identity.verifier"),
		client:  client,
		timeout: 3 * time.Second,
	}
}

// Close releases the underlying gRPC connection when this Verifier
// owns one. No-op for Wrap()ped instances.
func (v *Verifier) Close() error {
	if v == nil || v.conn == nil {
		return nil
	}
	return v.conn.Close()
}

// PresenceEntry is one (client_id, org_id) pair for ReportPresence.
// org_id is what the AUTH token role resolved into at handshake — the
// edge stamps it on each tick so identity-svc can compute online counts
// per org for the max_online_clients quota.
type PresenceEntry struct {
	ClientID int64
	OrgID    int64
	// ConnEpoch is the session's monotonic per-connection epoch (edge
	// unix-millis at session birth). identity-svc uses it to reject a
	// stale older connection's report from overwriting a newer one's
	// presence row. 0 = unknown (session predates the field).
	ConnEpoch int64
}

// ReportPresence forwards the set of currently active (client_id,
// org_id) pairs on this edge to identity-svc so the console can render
// live online status AND so the online-cap sweeper can count per-org.
// Best-effort: failures are logged but not returned upward — the loop
// retries on the next tick.
func (v *Verifier) ReportPresence(ctx context.Context, edgeNodeID int64, edgeLabel string, entries []PresenceEntry) error {
	if v == nil || v.client == nil {
		return fmt.Errorf("identity: not initialized")
	}
	cctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	// Build both the legacy flat id list and the new rich shape. The
	// server prefers `clients` when present; sending both keeps the
	// edge forward-and-backward-compatible across the 2026-05-28
	// identity-svc rollout (the proto change is additive).
	ids := make([]int64, 0, len(entries))
	pcs := make([]*pb.PresenceClient, 0, len(entries))
	for _, e := range entries {
		ids = append(ids, e.ClientID)
		pcs = append(pcs, &pb.PresenceClient{
			ClientId:  e.ClientID,
			OrgId:     e.OrgID,
			ConnEpoch: e.ConnEpoch,
		})
	}
	_, err := v.client.ReportClientPresence(cctx, &pb.ReportClientPresenceRequest{
		EdgeNodeId:    edgeNodeID,
		EdgeNodeLabel: edgeLabel,
		ClientIds:     ids,
		Clients:       pcs,
	})
	return err
}

// EdgeRegistration is the per-tick input to RegisterEdgeNode. The
// edge sends a refreshed snapshot every ~30s so identity-svc can age
// out dead edges in the directory ListEdges reads from.
type EdgeRegistration struct {
	EdgeNodeID int64
	NodeLabel  string
	Region     string
	PublicAddr string
	// BaseDomain is this node's visitor wildcard (cfg.BaseDomain) — the suffix a
	// tunnel hostname created on this node gets. Published so the console can
	// render "<prefix>.<base_domain>" from the directory alone.
	BaseDomain    string
	InternalAddr  string // VPC-internal addr for same-region peer forwarding; "" = no mesh
	ActiveClients int32
	EdgeClass     string // plan-tier pool: "shared" (default) | "dedicated"
	// edge/derp merge: the in-process mesh-relay endpoint, reported ONLY by a
	// PLATFORM merged node (role=both/relay + relay.kind=platform) so the
	// coordinator can list it in the platform DERP map. A self-hosted (BYOI)
	// relay leaves these 0 — it registers per-org via bff-edge instead. Relay
	// host = host(PublicAddr).
	RelayDerpPort int32
	RelayStunPort int32
}

// RegisterEdgeNode upserts this edge's directory row. Best-effort —
// errors are returned so the caller can log; presence reporting
// continues regardless.
func (v *Verifier) RegisterEdgeNode(ctx context.Context, in EdgeRegistration) error {
	if v == nil || v.client == nil {
		return fmt.Errorf("identity: not initialized")
	}
	cctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	_, err := v.client.RegisterEdgeNode(cctx, &pb.RegisterEdgeNodeRequest{
		EdgeNodeId:    in.EdgeNodeID,
		NodeLabel:     in.NodeLabel,
		Region:        in.Region,
		PublicAddr:    in.PublicAddr,
		BaseDomain:    in.BaseDomain,
		InternalAddr:  in.InternalAddr,
		ActiveClients: in.ActiveClients,
		EdgeClass:     in.EdgeClass,
		RelayDerpPort: in.RelayDerpPort,
		RelayStunPort: in.RelayStunPort,
	})
	return err
}

// GetOrgOnlineCount calls identity-svc's RPC of the same name. Used by
// the online-cap admit hook to decide whether to refuse a fresh AUTH.
// Returns count + nil on success. On RPC failure the caller MUST fail
// closed (refuse the session) — the alternative silently breaks the
// cap on a quota-svc / identity-svc blip.
func (v *Verifier) GetOrgOnlineCount(ctx context.Context, orgID int64) (int32, error) {
	if v == nil || v.client == nil {
		return 0, fmt.Errorf("identity: not initialized")
	}
	cctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	resp, err := v.client.GetOrgOnlineCount(cctx, &pb.GetOrgOnlineCountRequest{OrgId: orgID})
	if err != nil {
		return 0, err
	}
	return resp.GetCount(), nil
}

// EdgeInfo is one same-region directory entry the mesh resolver uses to
// build its peer address book. Only the fields peer forwarding needs.
type EdgeInfo struct {
	EdgeNodeID   int64
	Region       string
	InternalAddr string // VPC-internal forward addr; "" = peer not mesh-capable
	Healthy      bool
}

// listEdgesRPC is the optional capability needed for ListEdges. BOTH the
// direct pb.IdentityClient (cluster mode) AND bff_edge.BFFEdgeClient
// (bff-edge mode, since 2026-06-03) satisfy it — bff-edge now proxies
// ListEdges, forcing the region filter from the mTLS cert. The type
// assertion + ErrListEdgesUnsupported fallback is kept as a guard for any
// future transport that doesn't implement the method.
type listEdgesRPC interface {
	ListEdges(ctx context.Context, in *pb.ListEdgesRequest, opts ...grpc.CallOption) (*pb.ListEdgesResponse, error)
}

// ErrListEdgesUnsupported is returned when the transport can't issue
// ListEdges. With bff-edge now proxying it, this only fires for a
// transport that lacks the method.
var ErrListEdgesUnsupported = fmt.Errorf("identity: ListEdges not supported by this transport")

// ListEdges returns the edge directory for region (empty = all regions),
// mapped to the narrow EdgeInfo shape the mesh resolver consumes. Read-only;
// safe to poll on an interval.
func (v *Verifier) ListEdges(ctx context.Context, region string) ([]EdgeInfo, error) {
	if v == nil || v.client == nil {
		return nil, fmt.Errorf("identity: not initialized")
	}
	le, ok := v.client.(listEdgesRPC)
	if !ok {
		return nil, ErrListEdgesUnsupported
	}
	cctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	resp, err := le.ListEdges(cctx, &pb.ListEdgesRequest{Region: region})
	if err != nil {
		return nil, err
	}
	out := make([]EdgeInfo, 0, len(resp.GetItems()))
	for _, e := range resp.GetItems() {
		out = append(out, EdgeInfo{
			EdgeNodeID:   e.GetEdgeNodeId(),
			Region:       e.GetRegion(),
			InternalAddr: e.GetInternalAddr(),
			Healthy:      e.GetHealthy(),
		})
	}
	return out, nil
}

// Verify implements session.TokenVerifier. Returns (tenantID, workspaceID,
// clientID, ok). On failure ok=false and the other fields are empty.
func (v *Verifier) Verify(token string) (string, string, string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), v.timeout)
	defer cancel()

	resp, err := v.client.ValidateToken(ctx, &pb.ValidateTokenRequest{
		AccessToken: token,
	})
	if err != nil {
		v.logger.Warn("identity validate failed", "err", err)
		return "", "", "", false
	}
	if !resp.GetValid() {
		return "", "", "", false
	}

	// Parse the role string identity-svc emits, e.g.
	//   "org:42 ws:7 scopes:tunnel.read,tunnel.write"
	tenantID, workspaceID := "", ""
	for _, r := range resp.GetRoles() {
		for _, kv := range strings.Fields(r) {
			parts := strings.SplitN(kv, ":", 2)
			if len(parts) != 2 {
				continue
			}
			switch parts[0] {
			case "org":
				tenantID = parts[1]
			case "ws":
				workspaceID = parts[1]
			}
		}
	}

	// clientID: used a stable "alice-laptop" string from YAML. We
	// don't have a parallel concept on API keys, so we synthesize one
	// from the session_id (or first 12 chars of the token for API keys
	// so the value is stable across reconnects).
	clientID := resp.GetSessionId()
	if clientID == "" {
		// Trim "tk_" prefix; the next 8 chars are the public key prefix.
		t := strings.TrimPrefix(token, "tk_")
		if len(t) >= 8 {
			clientID = "key-" + t[:8]
		} else {
			clientID = "key-unknown"
		}
	}
	if tenantID == "" {
		tenantID = "unknown"
	}
	if workspaceID == "" {
		workspaceID = "default"
	}
	return tenantID, workspaceID, clientID, true
}
