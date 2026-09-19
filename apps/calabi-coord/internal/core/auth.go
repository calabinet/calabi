package core

import (
	"context"
	"errors"
)

// ErrAuthDenied is returned by Authenticator.Resolve for an unknown/invalid key.
var ErrAuthDenied = errors.New("core: auth key denied")

// Identity is the AUTHORITATIVE result of resolving a node's auth key: the
// meshnet it joins, plus any tags to stamp on the node for ACL matching. Both
// come from the key (self-hosted config / a tk_ key's grant) — a node NEVER
// self-asserts its meshnet or tags. The RPC layer trusts this and nothing else.
type Identity struct {
	Meshnet MeshnetID
	Tags    []string // e.g. ["tag:server"]; empty for a user-owned node
	// UserID is the human behind the key: for an api-key that is the person who
	// minted it (identity-svc bakes "actor:<id>" into its roles), not the key.
	// 0 when the key carries no attribution. Stamped on the node so the console
	// can answer "whose device is this" — the same question the Publish side
	// answers with Device.creator_user_id.
	UserID int64
	// Principal is what the key IS, in a form Reauthorize can check again later
	// without the key: "user:<id>" for a login token, "apikey:<id>" for an API
	// key. "" when the key names no one (a self-hosted key file's entries).
	// Stored on the node as Node.EnrolledBy.
	Principal string
}

// Authenticator resolves a node's auth key to its Identity, and says later
// whether an enrolled node may still come back without it.
//
// Platform build (MESH.1+): calls identity-svc to verify a tk_ auth key and
// map it to the acting org. Self-hosted build: a StaticAuth backed by the
// coordinator's config file. The interface keeps the RPC layer deployment-agnostic.
type Authenticator interface {
	Resolve(ctx context.Context, authKey string) (Identity, error)
	// Reauthorize is asked when an enrolled node registers again by proof of
	// its node key alone (node_reauth), with the meshnet and the principal it
	// enrolled as (Node.EnrolledBy). nil lets it back in; ErrAuthDenied means
	// that principal no longer admits it (a revoked key, a removed member);
	// any other error is the answer being unavailable, and refuses too.
	//
	// Part of the interface rather than an optional extra on purpose: an
	// authenticator that forgot it would otherwise let every node back in
	// forever, and nothing would say so.
	Reauthorize(ctx context.Context, meshnet MeshnetID, principal string) error
	// Spend is called once an enrollment with an auth key has proved the
	// device, just before it is recorded, with the principal Resolve named. A
	// key with a limited number of uses (a coordinator-minted one,
	// authkeys.go) counts one here, and the returned func takes it back if the
	// enrollment then fails. Keys without uses return a no-op func.
	//
	// Required for the same reason as Reauthorize: an authenticator that forgot
	// it would turn every one-time key into an unlimited one.
	Spend(ctx context.Context, principal string) (undo func(), err error)
}

// StaticAuth maps pre-shared auth keys to identities (meshnet + tags). Used by
// the self-hosted coordinator (keys come from its config file) and by tests/dev.
// Never used to gate the multi-tenant SaaS — that path resolves keys via
// identity-svc.
type StaticAuth struct {
	Keys map[string]Identity
}

// Resolve looks up authKey in the static table.
func (a StaticAuth) Resolve(_ context.Context, authKey string) (Identity, error) {
	if id, ok := a.Keys[authKey]; ok {
		return id, nil
	}
	return Identity{}, ErrAuthDenied
}

// Reauthorize lets every enrolled node back in. A key in the file admits a
// device; taking the key out stops new enrollments with it and does not remove
// the devices it admitted — that is what disabling or deleting a node is for.
func (StaticAuth) Reauthorize(context.Context, MeshnetID, string) error { return nil }

// Spend has nothing to count: a key-file entry admits any number of devices.
func (StaticAuth) Spend(context.Context, string) (func(), error) { return func() {}, nil }
