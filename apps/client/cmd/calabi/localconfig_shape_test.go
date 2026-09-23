package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The config file's two shapes.
//
// Until 1.15.0 the coordinator — which server this device belongs to and how it
// proves itself there — sat under `mesh:`, and the file was called
// tunnels.yaml. Both were wrong in the same way: `calabi http 8080` has no mesh
// and serves no tunnel from the file, yet it cannot reach an edge without
// `mesh.coord`. The settings moved to a `server:` block and the file to
// calabi.yaml.
//
// Every file already written is in the old shape, so the old shape loading is
// not a nicety here — it is the only thing standing between an upgrade and a
// fleet of machines that have forgotten which server they belong to.

const newShape = `
server:
  coord: coord.example.com:7012
  auth_key: ck_fromserverblock
  trust: pin
  pins: ["sha256:aaaa"]
  name: build-01
mesh:
  enabled: true
  advertise_routes: ["192.168.9.0/24"]
tunnels: []
`

const oldShape = `
mesh:
  enabled: true
  coord: coord.example.com:7012
  auth_key: ck_frommeshblock
  trust: pin
  pins: ["sha256:aaaa"]
  name: build-01
  advertise_routes: ["192.168.9.0/24"]
tunnels: []
`

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "calabi.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return p
}

// Both shapes must produce the same runtime lease, because everything
// downstream (edge_dial, the mesh runner, the console) reads cfg.Mesh.
func TestTheServerBlockAndTheOldMeshBlockLoadTheSame(t *testing.T) {
	for _, tc := range []struct{ name, body, wantKey string }{
		{"server block", newShape, "ck_fromserverblock"},
		{"pre-1.15 mesh block", oldShape, "ck_frommeshblock"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := loadLocalConfig(writeConfig(t, tc.body))
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if cfg.Mesh.Coord != "coord.example.com:7012" {
				t.Errorf("coord = %q", cfg.Mesh.Coord)
			}
			if cfg.Mesh.AuthKey != tc.wantKey {
				t.Errorf("auth_key = %q, want %q", cfg.Mesh.AuthKey, tc.wantKey)
			}
			if cfg.Mesh.Trust != "pin" || len(cfg.Mesh.Pins) != 1 || cfg.Mesh.Pins[0] != "sha256:aaaa" {
				t.Errorf("trust = %q pins = %v", cfg.Mesh.Trust, cfg.Mesh.Pins)
			}
			if cfg.Mesh.Name != "build-01" {
				t.Errorf("name = %q", cfg.Mesh.Name)
			}
			// A mesh-only knob, to prove the split moved the six and only the six.
			if len(cfg.Mesh.AdvertiseRoutes) != 1 || cfg.Mesh.AdvertiseRoutes[0] != "192.168.9.0/24" {
				t.Errorf("advertise_routes = %v", cfg.Mesh.AdvertiseRoutes)
			}
			if !cfg.Mesh.Enabled {
				t.Error("mesh.enabled was lost")
			}
			// mergeServerBlock leaves ONE truth in memory. A Server that still held
			// values would be a second place to read coord from, and the next person
			// to add a field would have to guess which one wins.
			if !reflect.DeepEqual(cfg.Server, serverConfig{}) {
				t.Errorf("Server should be emptied into Mesh after loading, got %+v", cfg.Server)
			}
		})
	}
}

// Writing always produces the new shape, whichever shape was read. This is the
// migration: the console saving anything at all is what converts a file.
func TestSavingRewritesTheOldShapeIntoTheServerBlock(t *testing.T) {
	cfg, err := loadLocalConfig(writeConfig(t, oldShape))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	out, err := marshalLocalConfig(*cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(out)

	if !strings.Contains(got, "server:") {
		t.Errorf("no server block after saving:\n%s", got)
	}
	// The six must not ALSO remain under mesh: a file carrying both is a file
	// with two answers, and mergeServerBlock's tie-break would be load-bearing
	// forever after.
	meshBlock := got[strings.Index(got, "mesh:"):]
	if end := strings.Index(meshBlock, "\ntunnels:"); end >= 0 {
		meshBlock = meshBlock[:end]
	}
	for _, moved := range []string{"coord:", "auth_key:", "trust:", "pins:", "name:"} {
		if strings.Contains(meshBlock, moved) {
			t.Errorf("mesh block still carries %s after saving:\n%s", moved, meshBlock)
		}
	}
	if !strings.Contains(meshBlock, "advertise_routes:") || !strings.Contains(meshBlock, "enabled: true") {
		t.Errorf("mesh block lost its own settings:\n%s", meshBlock)
	}

	// And it round-trips: nothing was dropped on the way through.
	back, err := loadLocalConfig(writeConfig(t, got))
	if err != nil {
		t.Fatalf("reload what we wrote: %v", err)
	}
	if back.Mesh.Coord != cfg.Mesh.Coord || back.Mesh.AuthKey != cfg.Mesh.AuthKey ||
		back.Mesh.Name != cfg.Mesh.Name || back.Mesh.Trust != cfg.Mesh.Trust ||
		len(back.Mesh.Pins) != len(cfg.Mesh.Pins) {
		t.Errorf("round trip changed the lease:\n got %+v\nwant %+v", back.Mesh, cfg.Mesh)
	}
}

// marshalLocalConfig takes its config by value and moves six fields out of the
// mesh block. A caller that went on running off the same config afterwards must
// not find its coordinator missing — which is what a pointer receiver here
// would have caused, silently, on the next save the daemon performed.
func TestSavingDoesNotDisarmTheCallersConfig(t *testing.T) {
	cfg, err := loadLocalConfig(writeConfig(t, newShape))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := marshalLocalConfig(*cfg); err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if cfg.Mesh.Coord == "" || cfg.Mesh.AuthKey == "" {
		t.Fatalf("saving emptied the live config: %+v", cfg.Mesh)
	}
}

// `server:` means two different things depending on its shape, and the file is
// refused or accepted accordingly.
//
// The scalar is the withdrawn edge setting (removedEdgeKeys): a file that still
// carries it is refused loudly, because silently ignoring it would leave someone
// convinced they had pointed the client at an edge. The mapping is the current
// schema. Reading the key name alone cannot tell them apart.
func TestServerIsRefusedAsAnEdgeURLAndAcceptedAsABlock(t *testing.T) {
	_, err := loadLocalConfig(writeConfig(t, "server: https://edge.example.com:7000\ntunnels: []\n"))
	if err == nil {
		t.Fatal("a config still naming the edge was accepted")
	}
	if !strings.Contains(err.Error(), "server") {
		t.Errorf("the error should name the setting to remove: %v", err)
	}

	cfg, err := loadLocalConfig(writeConfig(t, newShape))
	if err != nil {
		t.Fatalf("the server BLOCK was refused as if it named an edge: %v", err)
	}
	if cfg.Mesh.Coord == "" {
		t.Error("the server block was stripped instead of read")
	}
}

// The other removed edge keys are still refused, and still refused at the TOP
// level only: `trust` and `pins` are legitimate names inside `server:`, and the
// strip runs before the decoder ever sees them.
func TestTrustAndPinsInsideTheServerBlockAreNotMistakenForEdgeSettings(t *testing.T) {
	if _, err := loadLocalConfig(writeConfig(t, "trust: pin\npins: [\"sha256:aaaa\"]\ntunnels: []\n")); err == nil {
		t.Error("top-level trust/pins should still be refused")
	}
	if _, err := loadLocalConfig(writeConfig(t, newShape)); err != nil {
		t.Errorf("trust/pins inside server: %v", err)
	}
}

// --- the file's name ---------------------------------------------------------

func TestTheOldFileNameIsAdoptedOnce(t *testing.T) {
	dir := isolateDataDir(t)
	old := filepath.Join(dir, "tunnels.yaml")
	if err := os.WriteFile(old, []byte(oldShape), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Before the rename, the old file is still the one to read: a machine must
	// never be told it has no config because the rename has not happened yet.
	if got := managedConfigPath(); got != old {
		t.Fatalf("managedConfigPath = %q, want the legacy file %q", got, old)
	}

	adoptLegacyManagedConfig(nil)

	want := filepath.Join(dir, "calabi.yaml")
	if got := managedConfigPath(); got != want {
		t.Fatalf("after adopting, managedConfigPath = %q, want %q", got, want)
	}
	if fileExists(old) {
		t.Error("the old file was left behind; two files with one job is how a stale config gets edited")
	}
	body, err := os.ReadFile(want)
	if err != nil || !strings.Contains(string(body), "ck_frommeshblock") {
		t.Fatalf("the contents did not come with the name: %v\n%s", err, body)
	}

	adoptLegacyManagedConfig(nil) // idempotent
	if got := managedConfigPath(); got != want {
		t.Fatalf("second call moved it to %q", got)
	}
}

// A machine that already has the new file keeps it. Adopting here would
// overwrite a current config with whatever an older binary last wrote.
func TestAdoptingNeverOverwritesTheCurrentFile(t *testing.T) {
	dir := isolateDataDir(t)
	current := filepath.Join(dir, "calabi.yaml")
	if err := os.WriteFile(current, []byte(newShape), 0o600); err != nil {
		t.Fatalf("seed new: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tunnels.yaml"), []byte(oldShape), 0o600); err != nil {
		t.Fatalf("seed old: %v", err)
	}

	adoptLegacyManagedConfig(nil)

	body, err := os.ReadFile(current)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(body), "ck_fromserverblock") {
		t.Fatalf("the current config was replaced by the legacy one:\n%s", body)
	}
}

// yamlBlock returns the lines under a top-level key, so a test can assert that
// a value is in the block it belongs to rather than merely somewhere in the
// file. `strings.Contains(whole, addr)` passes just as happily when a setting
// lands in the wrong section, which is the mistake worth catching here.
func yamlBlock(doc, key string) string {
	lines := strings.Split(doc, "\n")
	start := -1
	for i, line := range lines {
		if start < 0 && line == key {
			start = i + 1
			continue
		}
		// The block ends at the next line that starts in column 0.
		if start >= 0 && line != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			return strings.Join(lines[start:i], "\n")
		}
	}
	if start < 0 {
		return ""
	}
	return strings.Join(lines[start:], "\n")
}

func TestYamlBlockReadsOneSection(t *testing.T) {
	const doc = "# header\nserver:\n  coord: a.example.com\nmesh:\n  coord: b.example.com\ntunnels: []\n"
	if got := yamlBlock(doc, "server:"); got != "  coord: a.example.com" {
		t.Errorf("server block = %q", got)
	}
	if got := yamlBlock(doc, "mesh:"); got != "  coord: b.example.com" {
		t.Errorf("mesh block = %q", got)
	}
	if got := yamlBlock(doc, "absent:"); got != "" {
		t.Errorf("missing key = %q, want empty", got)
	}
	// The point of the helper: a value in the wrong section must not match.
	if strings.Contains(yamlBlock(doc, "server:"), "b.example.com") {
		t.Error("the server block leaked into the mesh block")
	}
}
