package core

import (
	"context"
	"errors"
)

// ErrAuthDenied is returned by Authenticator.Resolve for an unknown/invalid key.
var ErrAuthDenied = errors.New("core: auth key denied")

// Identity is the AUTHORITATIVE result of resolving a node's auth key: the
// meshnet it joins, plus any tags to stamp on the node for ACL matching. Both
// come from the key (community config / a tk_ key's grant) — a node NEVER
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
}

// Authenticator resolves a node's auth key to its Identity.
//
// Platform build (MESH.1+): calls identity-svc to verify a tk_ auth key and
// map it to the acting org. Community build: a StaticAuth backed by the
// coordinator's config file. The interface keeps the RPC layer edition-agnostic.
type Authenticator interface {
	Resolve(ctx context.Context, authKey string) (Identity, error)
}

// StaticAuth maps pre-shared auth keys to identities (meshnet + tags). Used by
// the community coordinator (keys come from its config file) and by tests/dev.
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
