package statusapi

// Shared test helpers for this package.
//
// isolateCreds lived in repro_localconsole_test.go until a second test needed
// it. That file is a security-audit repro, and export-public.sh DELETES every
// repro_*_test.go on its way to the public tree — so the helper compiled here
// and vanished there, and `go vet` on the exported tree failed with "undefined:
// isolateCreds" on a file that had not been touched. A helper two tests share
// must not live in a file that only exists in the private tree.
//
// RUN: go test./apps/client/internal/platform/statusapi/

import (
	"path/filepath"
	"testing"

	"github.com/calabinet/calabi/apps/client/internal/creds"
)

// isolateCreds points creds + local token at a temp dir so the test never
// touches the developer's real daemon files. It returns the minted local token.
//
// Both variables, always: CALABI_CONFIG names the config FILE, and the local
// token resolves from the data dir without looking at it. Five mesh tests once
// set only CALABI_CONFIG and minted into the developer's real local_token.
func isolateCreds(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("CALABI_CONFIG", filepath.Join(dir, "config.json"))
	t.Setenv("CALABI_LOCAL_TOKEN", filepath.Join(dir, "local_token"))
	tok, err := creds.MintLocalToken()
	if err != nil {
		t.Fatalf("mint local token: %v", err)
	}
	return tok
}
