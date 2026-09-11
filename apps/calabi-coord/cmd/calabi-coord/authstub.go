package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
)

// devStaticAuth builds the self-hosted / dev StaticAuth. Two sources:
//   - CALABI_COORD_AUTHKEYS_FILE: a JSON map of auth-key -> {meshnet, tags}. This is
//     the self-hosted coordinator's real shape (multi-key + ACL tags); loaded when
//     set. Example:
//     { "key-a": { "meshnet": 1, "tags": ["tag:eng"] }, "key-b": { "meshnet": 1 } }
//   - else: a single key from CALABI_COORD_DEV_AUTH_KEY (default "dev-meshnet-1-key")
//     mapped to meshnet 1 with no tags — the zero-config dev/smoke path.
//
// Shared by both deployments in MESH.1. The platform build replaces this with an
// identity-svc Authenticator (tk_ keys -> org) — see wire_platform.go.
func devStaticAuth() (core.Authenticator, error) {
	if path := env("AUTHKEYS_FILE"); path != "" {
		a, err := loadStaticAuth(path)
		if err != nil {
			// Setting AUTHKEYS_FILE states the intent "these keys, and only
			// these". Falling back to the built-in key on an unreadable or
			// half-written file answered that with "anyone, into meshnet 1" —
			// using a key that is printed in the public source (audit finding
			// MESH-10). prodguard only checks that the variable is SET, so an
			// unmounted volume or a typo sailed straight past it.
			//
			// Fail hard regardless of environment: a broken key file is never a
			// reason to admit the world.
			return nil, fmt.Errorf("CALABI_COORD_AUTHKEYS_FILE=%s could not be loaded (%w) — "+
				"refusing to start rather than fall back to the built-in dev key", path, err)
		}
		return a, nil
	}
	key := env("DEV_AUTH_KEY")
	if key == "" {
		key = "dev-meshnet-1-key"
	}
	return core.StaticAuth{Keys: map[string]core.Identity{key: {Meshnet: 1}}}, nil
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
