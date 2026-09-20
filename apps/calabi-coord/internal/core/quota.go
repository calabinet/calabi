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
// deployment-agnostic seam for MESH.8 billing/quota: the self-hosted build wires a
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

// MemberNodeQuota is the member-aware half, kept as a SEPARATE interface on
// purpose: NodeQuota is what a self-hoster implements to plug this coordinator
// into their own platform, and widening it would break every outside
// implementation along with StaticNodeQuota and UnlimitedNodeQuota below. A
// backend that understands per-member caps implements both; the coordinator
// type-asserts for this one and falls back to NodeQuota when it is absent.
//
// ownerCurrent is how many ACTIVE nodes ownerUserID already has — the same
// caller-supplies-the-count contract as current, narrowed to one person.
type MemberNodeQuota interface {
	NodeQuota
	AdmitMember(ctx context.Context, t MeshnetID, ownerUserID int64, current, ownerCurrent int) (allowed bool, limit int, reason string, err error)
}

// UnlimitedNodeQuota admits everything. Default when no cap is configured (dev,
// and self-hosted self-hosts that don't set CALABI_COORD_NODE_QUOTA).
type UnlimitedNodeQuota struct{}

// Admit always allows (limit -1 = unlimited).
func (UnlimitedNodeQuota) Admit(context.Context, MeshnetID, int) (bool, int, string, error) {
	return true, -1, "", nil
}

// StaticNodeQuota caps every meshnet at the same node count. It's what the
// self-hosted coordinator and local/dev runs use (CALABI_COORD_NODE_QUOTA); the
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

// RelayRateSource supplies the rate a node should hold ITSELF to when sending
// over a platform relay. Values are kbps:
// a sustained rate and a short-burst ceiling. Both 0 = no self-limit.
//
// A separate seam from NodeQuota for the same reason MemberNodeQuota is: a
// self-hoster implementing NodeQuota to plug this coordinator into their own
// platform must not have to grow a method for a number that only means
// something on a relay fleet they do not run. Absent = nothing sent, which is
// exactly what a self-hosted coordinator should send.
//
// Implementations MUST degrade to (0, 0) on their own failures. Sending a
// number the coordinator is unsure of would have every node in the meshnet
// throttle itself on a quota hiccup — the failure mode has to be "no limit",
// never "some limit we guessed".
type RelayRateSource interface {
	RelayRateKbps(ctx context.Context, t MeshnetID) (sustained, burst uint32)
}
