package main

import "strings"

// splitCSV splits a comma-separated flag value into trimmed, non-empty items.
// Empty input yields nil. The raw items are validated later by whoever consumes
// them (e.g. the mesh runner's parseCIDRList), so a typo surfaces in that log
// rather than as a daemon boot crash.
//
// This lives in an UN-tagged file rather than daemon_mesh_platform.go
// It used to be build-gated; mesh.go calls it, so keeping it platform-only
// broke the self-hosted build with
// "undefined: splitCSV".
func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
