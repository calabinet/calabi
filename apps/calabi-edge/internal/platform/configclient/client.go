// Package configclient subscribes to config-svc's Subscribe stream so
// the edge gets live snapshot + delta notifications when tunnels are
// created / updated / deleted elsewhere in the cluster.
//
// plumbs hot-apply: deltas affecting THIS edge's own tunnels
// (route.edge_node_id == self) feed an Applier that mutates the local
// router; deltas for remote edges go into a "known elsewhere" log so
// HTTP/TCP visitors hitting the wrong edge can be told where to go.
package configclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/calabi/calabi/pkg/edge-proto/edgepb"
)

// Route is the per-tunnel projection we get from config-svc deltas.
// Mirrors apps/tunnel-svc/internal/events.Tunnel.
type Route struct {
	ID            int    `json:"id"`
	OrgID         int64  `json:"org_id"`
	WorkspaceID   int64  `json:"workspace_id"`
	ClientID      int64  `json:"client_id,omitempty"`
	Name          string `json:"name"`
	Type          string `json:"type"`
	LocalAddr     string `json:"local_addr,omitempty"`
	Domain        string `json:"domain"`
	Subdomain     string `json:"subdomain,omitempty"`
	RemotePort    int32  `json:"remote_port"`
	EdgeNodeID    int64  `json:"edge_node_id"`
	EdgeNodeLabel string `json:"edge_node_label"`
	Status        string `json:"status"`
	// ConfigJSON is the tunnel's server-authoritative config blob (security
	// policy: IP allowlist, …). config-svc already broadcasts it (tunnel-svc's
	// events.Tunnel carries it); the edge decodes it here so a console/SPA
	// policy edit can hot-update the live proxy via OnLocalDelta WITHOUT a
	// reconnect. Empty = no policy. See apps/calabi-edge/internal/policy.
	ConfigJSON string `json:"config_json"`
}

// Delta is what config-svc broadcasts. Mirrors apps/config-svc/internal/hub.Delta.
type Delta struct {
	ID    uint64 `json:"id"`
	Kind  string `json:"kind"` // "upsert" | "delete"
	Route Route  `json:"route"`
}

// Applier receives parsed routes from the stream.
//
// OnLocalDelta is called when route.edge_node_id == self; the edge MUST
// reflect the change in its local router (e.g. UnregisterByProxyID on
// delete). Failures are logged by configclient; the stream isn't broken.
//
// OnRemoteDelta is called for routes belonging to other edges; just notes them. wires cross-edge proxying.
type Applier interface {
	OnLocalDelta(Delta)
	OnRemoteDelta(Delta)
	OnSnapshot(routes []Route)
}

// RPC is the narrow subset of pb.ConfigClient the edge uses. bffedgeclient.ConfigAdapter (which wraps bff_edge.BFFEdgeClient.
// SubscribeConfig) satisfies the same shape, so the edge can pick
// either upstream at boot.
type RPC interface {
	Subscribe(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[pb.EdgeMessage, pb.ConfigMessage], error)
}

// Client maintains the subscription. Start spawns the goroutine; Close
// shuts it down.
type Client struct {
	addr       string
	edgeNodeID int64
	region     string
	version    string
	logger     *slog.Logger
	applier    Applier

	conn   *grpc.ClientConn // nil when StartWithClient was used
	rpc    RPC
	cancel context.CancelFunc
}

// Options configures the client.
type Options struct {
	Addr       string // host:port of config-svc
	EdgeNodeID int64
	Region     string
	Version    string
	// Applier is called for each parsed snapshot/delta. nil = log only.
	Applier Applier
}

// The direct-dial constructor was removed in F3 step 2b: every edge now
// reaches the control plane through bff-edge, so this package is only ever
// handed a ready client.
// StartWithClient is Start's sibling for bff-edge mode: the caller
// passes a pre-made RPC (typically bffedgeclient.NewConfigAdapter) so
// the subscription flows through the shared bff-edge connection instead
// of dialling config-svc directly.
func StartWithClient(parent context.Context, logger *slog.Logger, rpc RPC, opts Options) (*Client, error) {
	if rpc == nil {
		return nil, fmt.Errorf("configclient: nil RPC")
	}
	ctx, cancel := context.WithCancel(parent)
	c := &Client{
		edgeNodeID: opts.EdgeNodeID,
		region:     opts.Region,
		version:    opts.Version,
		logger:     logger.With("component", "configclient"),
		applier:    opts.Applier,
		rpc:        rpc,
		cancel:     cancel,
	}
	go c.runLoop(ctx)
	return c, nil
}

// Close stops the subscription goroutine and closes the gRPC connection
// when this Client owns one. No-op on the conn for StartWithClient
// instances (the caller owns the shared conn).
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.cancel()
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// runLoop opens the bidi stream and reconnects on transient errors.
func (c *Client) runLoop(ctx context.Context) {
	backoff := 1 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		if err := c.runOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
			c.logger.Warn("config stream ended; will reconnect",
				"err", err, "backoff", backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		// Clean disconnect (ctx.Done() inside runOnce) -> exit loop.
		return
	}
}

func (c *Client) runOnce(ctx context.Context) error {
	stream, err := c.rpc.Subscribe(ctx)
	if err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}

	// HelloEdge.
	if err := stream.Send(&pb.EdgeMessage{
		Kind: &pb.EdgeMessage_Hello{
			Hello: &pb.HelloEdge{
				EdgeNodeId: c.edgeNodeID,
				Region:     c.region,
				Version:    c.version,
			},
		},
	}); err != nil {
		return fmt.Errorf("send hello: %w", err)
	}

	// Heartbeats every 30s so the stream stays warm and config-svc can
	// notice dead edges.
	hbStop := make(chan struct{})
	go c.heartbeat(stream, hbStop)
	defer close(hbStop)

	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch m := msg.GetKind().(type) {
		case *pb.ConfigMessage_Snapshot:
			c.handleSnapshot(m.Snapshot)
		case *pb.ConfigMessage_Delta:
			c.handleDelta(m.Delta)
			// Best-effort ack so config-svc can log success counts.
			_ = stream.Send(&pb.EdgeMessage{
				Kind: &pb.EdgeMessage_Ack{
					Ack: &pb.Ack{DeltaId: m.Delta.GetDeltaId(), Ok: true},
				},
			})
		}
	}
}

func (c *Client) handleSnapshot(s *pb.Snapshot) {
	var routes []Route
	if len(s.GetBodyJson()) > 0 {
		if err := json.Unmarshal(s.GetBodyJson(), &routes); err != nil {
			c.logger.Warn("snapshot decode failed", "err", err)
			return
		}
	}
	c.logger.Info("config snapshot received",
		"sha", s.GetSha(),
		"routes", len(routes),
	)
	if c.applier != nil {
		c.applier.OnSnapshot(routes)
	}
}

func (c *Client) handleDelta(d *pb.Delta) {
	var delta Delta
	if err := json.Unmarshal(d.GetPatchJson(), &delta); err != nil {
		c.logger.Warn("delta decode failed", "err", err)
		return
	}
	local := delta.Route.EdgeNodeID == c.edgeNodeID
	c.logger.Info("config delta received",
		"id", d.GetDeltaId(),
		"kind", delta.Kind,
		"local", local,
		"route_id", delta.Route.ID,
		"edge", delta.Route.EdgeNodeID,
		"domain", delta.Route.Domain,
	)
	if c.applier == nil {
		return
	}
	if local {
		c.applier.OnLocalDelta(delta)
	} else {
		c.applier.OnRemoteDelta(delta)
	}
}

func (c *Client) heartbeat(stream grpc.BidiStreamingClient[pb.EdgeMessage, pb.ConfigMessage], stop <-chan struct{}) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			_ = stream.Send(&pb.EdgeMessage{
				Kind: &pb.EdgeMessage_Beat{
					Beat: &pb.Heartbeat{Ts: timestamppb.Now()},
				},
			})
		}
	}
}
