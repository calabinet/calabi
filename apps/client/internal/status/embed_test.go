// embed sanity tests. Verifies:
//   - go:embed pulls in ui/dist/index.html
//   - UIFileSystem() returns a non-empty fs.FS rooted at dist/
//   - Open("index.html") returns the SPA shell
//   - Total embedded bytes stay under the budget (4 MB raw)

package status

import (
	"io"
	"io/fs"
	"strings"
	"testing"
)

func TestUIFileSystem_EmbedsPlaceholder(t *testing.T) {
	root, err := UIFileSystem()
	if err != nil {
		t.Fatalf("UIFileSystem: %v", err)
	}
	f, err := root.Open("index.html")
	if err != nil {
		t.Fatalf("Open index.html: %v", err)
	}
	defer f.Close()
	body, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	// shipped the real Vite-built SPA. The shell only carries
	// the `<title>Calabi...</title>` plus the bootstrap <script>; the
	// page content lives in the JS bundle. Check for the title (proves
	// the right file got embedded) and the JS entry (proves Vite ran
	// and the assets reference is intact).
	bs := string(body)
	if !strings.Contains(bs, "Calabi") {
		t.Fatalf("expected SPA shell to contain 'Calabi'; got %q", bs)
	}
	if !strings.Contains(bs, `id="root"`) {
		t.Fatalf("expected SPA shell to have <div id=\"root\">; got %q", bs)
	}
}

func TestUIFileSystem_BinaryFootprintBounded(t *testing.T) {
	// budget: total embedded bytes < 4 MB. The SPA is currently
	// ~1.5 MB raw (~500 KB gzipped) — antd is the bulk. This test exists
	// so a future PR that accidentally embeds source maps or untranspiled
	// node_modules gets a clear failure message rather than a fat CLI.
	root, err := UIFileSystem()
	if err != nil {
		t.Fatalf("UIFileSystem: %v", err)
	}
	var total int64
	err = fs.WalkDir(root, ".", func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}
	const budget = 4 * 1024 * 1024
	if total > budget {
		t.Fatalf("ui/dist exceeds M7-S4 budget: %d bytes > %d", total, budget)
	}
}
