package configreload

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/calabi/calabi/apps/calabi-edge/internal/config"
)

// captureApplier records calls so tests can assert on them.
type captureApplier struct {
	mu          sync.Mutex
	tokens      [][]config.TokenEntry
	bases       []string
	tokensCount atomic.Int32
	basesCount  atomic.Int32
}

func (c *captureApplier) ApplyAcceptedTokens(t []config.TokenEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tokens = append(c.tokens, append([]config.TokenEntry(nil), t...))
	c.tokensCount.Add(1)
}

func (c *captureApplier) ApplyBaseDomain(b string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bases = append(c.bases, b)
	c.basesCount.Add(1)
}

func writeConfig(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestReloader_AppliesWhitelistedChanges(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "edge.yaml")
	writeConfig(t, path, formatYAML("localtest.me", []config.TokenEntry{{Token: "tok1", TenantID: "a"}}))

	initial, err := config.Load(path)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	ap := &captureApplier{}
	r := New(path, initial, ap, quietLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = r.Run(ctx) }()

	// Give the watcher a moment to register.
	time.Sleep(100 * time.Millisecond)

	// Mutation: change base_domain + add a token. Both are whitelisted.
	writeConfig(t, path, formatYAML("calabi.net", []config.TokenEntry{
		{Token: "tok1", TenantID: "a"},
		{Token: "tok2", TenantID: "b"},
	}))

	if !waitFor(func() bool {
		return ap.basesCount.Load() >= 1 && ap.tokensCount.Load() >= 1
	}, 3*time.Second) {
		t.Fatalf("applier never fired: tokens=%d bases=%d", ap.tokensCount.Load(), ap.basesCount.Load())
	}

	ap.mu.Lock()
	defer ap.mu.Unlock()
	if got := ap.bases[len(ap.bases)-1]; got != "calabi.net" {
		t.Fatalf("base_domain: got %q want calabi.net", got)
	}
	if len(ap.tokens) == 0 || len(ap.tokens[len(ap.tokens)-1]) != 2 {
		t.Fatalf("accepted_tokens: %+v", ap.tokens)
	}
}

func TestReloader_RefusesNonWhitelistedField(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "edge.yaml")
	writeConfig(t, path, formatYAML("localtest.me", []config.TokenEntry{{Token: "tok1", TenantID: "a"}}))

	initial, _ := config.Load(path)
	ap := &captureApplier{}
	r := New(path, initial, ap, quietLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = r.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)

	// Mutation: change node_id (NOT whitelisted). Reload should be
	// refused and the applier should NOT be called.
	writeConfig(t, path, `node_id: changed-edge
region: test
control:
  addr: ":7443"
http:
  addr: ":8080"
  base_domain: "localtest.me"
admin:
  addr: ":9101"
accepted_tokens:
  - token: "tok1"
    tenant_id: "a"
log:
  level: info
  format: text
`)

	// Wait past the debounce window + some slack.
	time.Sleep(800 * time.Millisecond)

	if ap.basesCount.Load() != 0 || ap.tokensCount.Load() != 0 {
		t.Fatalf("applier fired despite non-whitelisted change: tokens=%d bases=%d",
			ap.tokensCount.Load(), ap.basesCount.Load())
	}
}

func formatYAML(base string, tokens []config.TokenEntry) string {
	tokStr := ""
	for _, e := range tokens {
		tokStr += "  - token: \"" + e.Token + "\"\n    tenant_id: \"" + e.TenantID + "\"\n"
	}
	return `node_id: test-edge
region: test
control:
  addr: ":7443"
http:
  addr: ":8080"
  base_domain: "` + base + `"
admin:
  addr: ":9101"
accepted_tokens:
` + tokStr + `log:
  level: info
  format: text
`
}

func waitFor(check func() bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if check() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
}
