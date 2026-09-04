// Package ent holds the ent-generated database client for calabi-coord's
// PLATFORM node store (MESH.8c). It lives under internal/platform so the
// deployment-agnostic core (and the self-hosted coordinator) never link it —
// a self-hosted coordinator keeps the in-memory NodeStore.
package ent

// Codegen tool pinned to v0.14.4 (the version that generated the committed
// code) and run without -mod=mod so `go generate` works under go.work
// workspace mode and reproduces the committed output exactly.
//go:generate go run entgo.io/ent/cmd/ent@v0.14.6 generate ./schema
