// adapters.go — thin wrappers that paper over NAME differences between
// bff_edge.BFFEdgeClient and the client surfaces the edge programs against.
//
// Two methods differ in name (the bff_edge names are coherent in their own
// namespace rather than mirroring the legacy ones):
//
//	Quota.GetEffective    vs  bff_edge.GetEffectiveQuota
//	Config.Subscribe      vs  bff_edge.SubscribeConfig
//
// Everything else (ValidateToken, ClaimTunnel, GetCert, …) matches exactly, so
// the raw BFFEdgeClient satisfies those clients' narrow interfaces directly.
//
// Since F3 step 2b these adapters convert NOTHING: the edge's platform clients
// are typed by the edge contract itself (pkg/edge-proto/edgepb), because every
// edge now reaches the control plane through bff-edge. The re-encoding bridges
// that briefly lived here — for the window where one binary had to speak both
// the contract types and the control-plane types — are gone with the
// direct-dial path that needed them.

package bffedgeclient

import (
	"context"

	"google.golang.org/grpc"

	edgepb "github.com/calabi/calabi/pkg/edge-proto/edgepb"
)

// ===================== Quota adapter =====================

// QuotaAdapter exposes a Quota.GetEffective-shaped method by forwarding to
// BFFEdgeClient.GetEffectiveQuota.
type QuotaAdapter struct {
	Client edgepb.BFFEdgeClient
}

// NewQuotaAdapter wires up the adapter.
func NewQuotaAdapter(c edgepb.BFFEdgeClient) *QuotaAdapter {
	return &QuotaAdapter{Client: c}
}

// GetEffective mirrors the quota client's GetEffective.
func (a *QuotaAdapter) GetEffective(
	ctx context.Context,
	in *edgepb.GetEffectiveRequest,
	opts ...grpc.CallOption,
) (*edgepb.EffectiveQuota, error) {
	return a.Client.GetEffectiveQuota(ctx, in, opts...)
}

// ===================== Config adapter =====================

// ConfigAdapter wraps BFFEdgeClient.SubscribeConfig under the Config.Subscribe
// name so apps/calabi-edge/internal/platform/configclient programs against one
// small interface.
type ConfigAdapter struct {
	Client edgepb.BFFEdgeClient
}

// NewConfigAdapter wires up the adapter.
func NewConfigAdapter(c edgepb.BFFEdgeClient) *ConfigAdapter {
	return &ConfigAdapter{Client: c}
}

// Subscribe mirrors the config client's Subscribe by forwarding to
// SubscribeConfig. The stream types line up exactly — both sides are the edge
// contract now — so the stream is returned as-is.
func (a *ConfigAdapter) Subscribe(
	ctx context.Context,
	opts ...grpc.CallOption,
) (grpc.BidiStreamingClient[edgepb.EdgeMessage, edgepb.ConfigMessage], error) {
	return a.Client.SubscribeConfig(ctx, opts...)
}
