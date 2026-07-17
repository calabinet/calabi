// SPA cache-header tests.
//
// Regression guard for a real production bug: the daemon served the SPA shell
// with Content-Type and nothing else. The embedded FS has zero-value modtimes,
// so net/http emits neither Last-Modified nor ETag — with no cache directive at
// all, the desktop WebView heuristically cached the shell and kept rendering the
// PREVIOUS release's SPA (pinned to its old asset hashes) after an upgrade. The
// daemon underneath was new; the UI on top was stale, which looked exactly like
// "the fix didn't ship".
//
// Contract: shell = never cached, hashed assets = cached immutably.

package status

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleIndex_ShellIsNotCacheable(t *testing.T) {
	// NewServer calls logger.With, so a nil *slog.Logger panics — discard instead.
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewServer(lg, New("test", "127.0.0.1:0"), "127.0.0.1:0")
	rr := httptest.NewRecorder()
	s.handleIndex(rr, httptest.NewRequest("GET", "/", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /: got %d, want 200", rr.Code)
	}
	cc := rr.Header().Get("Cache-Control")
	if cc == "" {
		t.Fatal("GET / has no Cache-Control: the WebView will heuristically cache " +
			"the shell and keep serving the previous release's SPA after an upgrade")
	}
	if !strings.Contains(cc, "no-cache") && !strings.Contains(cc, "no-store") {
		t.Errorf("GET / Cache-Control = %q, want no-cache/no-store", cc)
	}
}

func TestImmutableAssets_HashedBundlesAreCachedHard(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("console.log(1)"))
	})
	rr := httptest.NewRecorder()
	immutableAssets(inner).ServeHTTP(rr, httptest.NewRequest("GET", "/assets/index-abc123.js", nil))

	cc := rr.Header().Get("Cache-Control")
	if !strings.Contains(cc, "immutable") {
		t.Errorf("hashed asset Cache-Control = %q, want an immutable directive", cc)
	}
}
