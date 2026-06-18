// Package admin is deprecated. The /healthz + /readyz +
// /metrics surface has moved to pkg/observability so every control-plane
// service shares the baseline.
//
// This file remains only to avoid breaking external `go install` invocations
// that might still target the old import path. Delete.
package admin
