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

	"github.com/calabinet/calabi/apps/calabi-edge/internal/config"
)

// testCoordKey makes the test configs valid standalone edges: an edge with no
// way to accept a client does not load at all, and a reload refused for THAT
// reason would pass these tests for the wrong one.
const testCoordKey = "xMqLvONWcTdghKQ4cwvVQ81FuXDj/0npFphl4BujbdA="

// captureApplier records calls so tests can assert on them.
type captureApplier struct {
	mu         sync.Mutex
	bases      []string
	basesCount atomic.Int32
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
	writeConfig(t, path, formatYAML("localtest.me"))

	hermeticEnv(t)
	initial, _, err := config.LoadEffective(path)
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

	// Mutation: change base_domain, which is whitelisted.
	writeConfig(t, path, formatYAML("calabi.net"))

	if !waitFor(func() bool { return ap.basesCount.Load() >= 1 }, 3*time.Second) {
		t.Fatalf("applier never fired: bases=%d", ap.basesCount.Load())
	}

	ap.mu.Lock()
	defer ap.mu.Unlock()
	if got := ap.bases[len(ap.bases)-1]; got != "calabi.net" {
		t.Fatalf("base_domain: got %q want calabi.net", got)
	}
}

func TestReloader_RefusesNonWhitelistedField(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "edge.yaml")
	writeConfig(t, path, formatYAML("localtest.me"))

	hermeticEnv(t)
	initial, _, err := config.LoadEffective(path)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	ap := &captureApplier{}
	r := New(path, initial, ap, quietLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = r.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)

	// Mutation: change node_id (NOT whitelisted). Reload should be
	// refused and the applier should NOT be called.
	writeConfig(t, path, `mode: standalone
coord_pubkey: "`+testCoordKey+`"
node_id: changed-edge
region: test
public:
  host: test-edge.example
control:
  addr: ":7443"
http:
  addr: ":8080"
  base_domain: "localtest.me"
admin:
  addr: ":9101"
log:
  level: info
  format: text
`)

	// Wait past the debounce window + some slack.
	time.Sleep(800 * time.Millisecond)

	if ap.basesCount.Load() != 0 {
		t.Fatalf("applier fired despite non-whitelisted change: bases=%d", ap.basesCount.Load())
	}
}

func formatYAML(base string) string {
	return `mode: standalone
coord_pubkey: "` + testCoordKey + `"
node_id: test-edge
region: test
public:
  host: test-edge.example
control:
  addr: ":7443"
http:
  addr: ":8080"
  base_domain: "` + base + `"
admin:
  addr: ":9101"
log:
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
