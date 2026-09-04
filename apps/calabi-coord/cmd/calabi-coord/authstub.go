package main

import (
	"encoding/json"
	"os"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
)

// devStaticAuth builds the community/dev StaticAuth. Two sources:
//   - CALABI_COORD_AUTHKEYS_FILE: a JSON map of auth-key -> {meshnet, tags}. This is
//     the community coordinator's real shape (multi-key + ACL tags); loaded when
//     set. Example:
//     { "key-a": { "meshnet": 1, "tags": ["tag:eng"] }, "key-b": { "meshnet": 1 } }
//   - else: a single key from CALABI_COORD_DEV_AUTH_KEY (default "dev-meshnet-1-key")
//     mapped to meshnet 1 with no tags — the zero-config dev/smoke path.
//
// Shared by both editions in MESH.1. The platform build replaces this with an
// identity-svc Authenticator (tk_ keys -> org) — see wire_platform.go.
func devStaticAuth() core.Authenticator {
	if path := env("AUTHKEYS_FILE"); path != "" {
		if a, err := loadStaticAuth(path); err == nil {
			return a
		}
		// Fall through to the single-key default on a bad/unreadable file — this
		// is the DEV stub. The real community coordinator config surfaces load
		// errors at startup (MESH.9).
	}
	key := env("DEV_AUTH_KEY")
	if key == "" {
		key = "dev-meshnet-1-key"
	}
	return core.StaticAuth{Keys: map[string]core.Identity{key: {Meshnet: 1}}}
}

// loadStaticAuth reads a JSON auth-keys file (key -> {meshnet, tags}) into a
// StaticAuth.
func loadStaticAuth(path string) (core.StaticAuth, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return core.StaticAuth{}, err
	}
	var m map[string]struct {
		Meshnet int64    `json:"meshnet"`
		Tags    []string `json:"tags"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return core.StaticAuth{}, err
	}
	keys := make(map[string]core.Identity, len(m))
	for k, v := range m {
		keys[k] = core.Identity{Meshnet: core.MeshnetID(v.Meshnet), Tags: v.Tags}
	}
	return core.StaticAuth{Keys: keys}, nil
}
