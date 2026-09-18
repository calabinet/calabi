package selfupdate

import (
	"encoding/json"
	"testing"
	"time"
)

// updatekitOutput is a manifest COPIED VERBATIM from what
// `scripts/updatekit merge --critical --min-supported 1.10.0 --rollback` followed
// by `updatekit rollout --hours 48` and `--cap 30` writes (2026-09-16, a
// throwaway key). Not hand-written to match this package's struct tags —
// that would only prove the struct agrees with itself.
//
// updatekit is a separate module: it cannot import this package and there is no
// compiler check that the two agree on field names. A rename on either side is
// silently lossy, and the failure mode is the worst kind — the manifest still
// parses, still verifies, and the flag that was supposed to force an install
// just is not there. `rollback` already lived through exactly that: updatekit's
// struct did not declare it, so any merge run over a rollback manifest erased
// it and re-signed the result, which then looked perfectly valid.
const updatekitOutput = `{
  "version": "1.12.0",
  "pub_date": "2026-09-16T12:50:46Z",
  "rollback": true,
  "critical": true,
  "min_supported": "1.10.0",
  "rollout": {
    "start": "2026-09-16T12:50:46Z",
    "hours": 48,
    "cap_percent": 30
  },
  "platforms": {
    "darwin-universal": {
      "url": "https://example.test/d.pkg",
      "sha256": "ec09b58055ca508e9b7f2e3a1d5a843bf7d18c6eef631f5e0007858c34bc62f4",
      "signature": "rVNmpNEESrDXazwI3aMhJlfoS7q7jvU1Nhnv2E+5rj7kTK8KJwU3ruQCDD6AYytMJWvTjh0SHu5rERqL5Ol7BA=="
    }
  }
}`

func TestManifestReadsEveryFieldUpdatekitWrites(t *testing.T) {
	var m Manifest
	if err := json.Unmarshal([]byte(updatekitOutput), &m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if m.Version != "1.12.0" {
		t.Errorf("version = %q", m.Version)
	}
	// Each of these changes what happens on someone's machine without asking
	// them. A silent false here is a security release that installs like a
	// routine one, or a floor that never forces anything.
	if !m.Critical {
		t.Error("critical did not survive the wire — a security release would install like a routine one")
	}
	if m.MinSupported != "1.10.0" {
		t.Errorf("min_supported = %q, want 1.10.0 — the floor would never force anything", m.MinSupported)
	}
	if !m.Rollback {
		t.Error("rollback did not survive the wire — the anti-rollback floor would refuse the documented recovery")
	}
	// A schedule that did not survive is a release that reaches everyone at
	// once — exactly what the rollout was published to prevent.
	if r := m.Rollout; r == nil || r.Hours != 48 || r.CapPercent == nil || *r.CapPercent != 30 ||
		!r.Start.Equal(time.Date(2026, 9, 16, 12, 50, 46, 0, time.UTC)) {
		t.Errorf("rollout did not survive the wire: %+v", m.Rollout)
	}
	a, ok := m.Platforms["darwin-universal"]
	if !ok || a.SHA256 == "" || a.Signature == "" || a.URL == "" {
		t.Errorf("platform entry did not decode: %+v (ok=%v)", a, ok)
	}
}

// The reverse direction: every field this package can act on must be one
// updatekit actually knows how to write. A flag the client honours but no tool
// can produce is a feature that exists only in tests.
func TestEveryActionableManifestFieldIsProducible(t *testing.T) {
	var got map[string]any
	if err := json.Unmarshal([]byte(updatekitOutput), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, field := range []string{"version", "critical", "min_supported", "rollback", "rollout", "platforms"} {
		if _, ok := got[field]; !ok {
			t.Errorf("%q is acted on by this package but updatekit does not emit it", field)
		}
	}
}
