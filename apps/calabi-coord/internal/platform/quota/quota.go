// Package quota caps a meshnet's node count against the owning org's plan by
// asking a platform over QuotaHooks (admit kind "mesh_node", quotas key
// "max_mesh_nodes"). It is one of the two seat-cap postures a coordinator can
// run — the other is core.StaticNodeQuota from CALABI_COORD_NODE_QUOTA — selected
// by CALABI_COORD_QUOTA_ADDR; prodguard.go refuses production with neither, because
// silently unlimited seats is a billing hole nobody notices for months.
// Mirrors tunnel-svc's quotaclient (best-effort, degrade-open).
package quota

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
	pb "github.com/calabi/calabi/pkg/hooks-proto/hookspb"
)

// admitKind is the quota-svc CheckAdmit kind for mesh nodes; quota-svc maps it
// to the plan's "max_mesh_nodes" quota (keyByKind in quota-svc/internal/store).
const admitKind = "mesh_node"

// Client is a core.NodeQuota backed by quota-svc.
type Client struct {
	conn    *grpc.ClientConn
	rpc     pb.QuotaHooksClient
	logger  *slog.Logger
	timeout time.Duration
}

// Dial connects to quota-svc. Empty addr is an error (the caller decides whether
// to fall back to a static cap).
func Dial(logger *slog.Logger, addr string) (*Client, error) {
	if addr == "" {
		return nil, fmt.Errorf("quota: empty addr")
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("quota dial: %w", err)
	}
	return &Client{conn: conn, rpc: pb.NewQuotaHooksClient(conn), logger: logger.With("component", "mesh-quota"), timeout: 2 * time.Second}, nil
}

// Close releases the gRPC connection.
func (c *Client) Close() error { return c.conn.Close() }

// Admit implements core.NodeQuota: is (current + 1) mesh nodes allowed for this
// meshnet's org? A quota-svc error degrades OPEN (allowed, limit -1) so a
// control-plane hiccup can't lock a whole meshnet out of enrolling — matching
// tunnel-svc. meshnet id == org id (one org = one meshnet).
func (c *Client) Admit(ctx context.Context, t core.MeshnetID, current int) (bool, int, string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, err := c.rpc.CheckAdmit(ctx, &pb.CheckAdmitRequest{
		OrgId:   int64(t),
		Kind:    admitKind,
		Delta:   1,
		Current: int64(current),
	})
	if err != nil {
		c.logger.Warn("mesh_node admit rpc failed; degrading open", "meshnet", int64(t), "err", err)
		return true, -1, "", nil
	}
	return resp.GetAllowed(), int(resp.GetLimit()), resp.GetReason(), nil
}
