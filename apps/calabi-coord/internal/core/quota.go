package core

import (
	"context"
	"errors"
	"fmt"
)

// ErrNodeQuotaExceeded is returned by Register when admitting a NEW node would
// exceed the meshnet's node cap. The RPC layer maps it to ResourceExhausted so
// the client sees a clear "over quota" refusal (not an internal error).
var ErrNodeQuotaExceeded = errors.New("core: mesh node quota exceeded")

// NodeQuota decides whether a meshnet may enroll one more node. It is the
// edition-agnostic seam for MESH.8 billing/quota: the community build wires a
// static (or unlimited) cap; the platform build wraps quota-svc (kind
// "mesh_node") behind this same interface, so core never imports pkg/api.
//
// current is the meshnet's existing node count (the resource owner supplies it,
// matching quota-svc's CheckAdmit contract). Admit reports whether adding one
// takes it over the limit. Implementations degrade OPEN on their own transient
// failures (return allowed=true) — a quota backend hiccup must not lock a whole
// meshnet out of enrolling, matching tunnel-svc's quotaclient policy.
type NodeQuota interface {
	Admit(ctx context.Context, t MeshnetID, current int) (allowed bool, limit int, reason string, err error)
}

// UnlimitedNodeQuota admits everything. Default when no cap is configured (dev,
// and community self-hosts that don't set CALABI_COORD_NODE_QUOTA).
type UnlimitedNodeQuota struct{}

// Admit always allows (limit -1 = unlimited).
func (UnlimitedNodeQuota) Admit(context.Context, MeshnetID, int) (bool, int, string, error) {
	return true, -1, "", nil
}

// StaticNodeQuota caps every meshnet at the same node count. It's what the
// community coordinator and local/dev runs use (CALABI_COORD_NODE_QUOTA); the
// multi-tenant per-plan cap is the platform quota-svc impl. Limit <= 0 means
// unlimited.
type StaticNodeQuota struct{ Limit int }

// Admit allows while current < Limit (adding one stays within the cap).
func (q StaticNodeQuota) Admit(_ context.Context, _ MeshnetID, current int) (bool, int, string, error) {
	if q.Limit <= 0 {
		return true, -1, "", nil
	}
	if current >= q.Limit {
		return false, q.Limit, fmt.Sprintf("node limit %d reached for this meshnet", q.Limit), nil
	}
	return true, q.Limit, "", nil
}
