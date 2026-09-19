package configreload

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/calabi/calabi/apps/calabi-edge/internal/config"
)

// hotPaths is what a reload may change. Everything else must be refused.
var hotPaths = map[string]bool{
	"base_domain":      true,
	"http.base_domain": true,
}

// edgeEnv is every variable the load pipeline reads (config.ApplyEnv plus
// CALABI_ENV for the production posture check).
var edgeEnv = []string{
	"CALABI_ENV",
	"CALABI_EDGE_MODE",
	"CALABI_EDGE_ROLE",
	"CALABI_EDGE_ADMIN_ADDR",
	"CALABI_EDGE_RELAY_KIND",
	"CALABI_EDGE_RELAY_LABEL",
	"CALABI_EDGE_RELAY_COORD_PUBKEY",
	"CALABI_EDGE_RELAY_DERP_PORT",
	"CALABI_EDGE_RELAY_STUN_PORT",
	"CALABI_EDGE_RELAY_REQUIRE_AUTH",
	"CALABI_EDGE_COORD_PUBKEY",
	"CALABI_EDGE_COORD_PUBKEY_FILE",
}

// hermeticEnv blanks every variable the pipeline reads (blank = unset to
// ApplyEnv), so the developer's shell can't decide a test's outcome.
func hermeticEnv(t *testing.T) {
	t.Helper()
	for _, k := range edgeEnv {
		t.Setenv(k, "")
	}
}

// newTestReloader builds the baseline exactly as main.go does and returns
// a reloader whose reload() the test drives directly — no watcher, no
// timing.
func newTestReloader(t *testing.T, yaml string) (*Reloader, *captureApplier, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "edge.yaml")
	writeConfig(t, path, yaml)
	initial, _, err := config.LoadEffective(path)
	if err != nil {
		t.Fatalf("boot load: %v", err)
	}
	ap := &captureApplier{}
	return New(path, initial, ap, quietLogger()), ap, path
}

// TestEveryFieldButTheWhitelistIsRestartOnly walks every leaf of
// config.Config by reflection, changes it alone, and requires the check to
// refuse it by name — unless it is in hotPaths. A field added to Config
// tomorrow is covered without anyone touching this test.
func TestEveryFieldButTheWhitelistIsRestartOnly(t *testing.T) {
	base := config.Default()
	visited := map[string]bool{}

	for path, index := range leafFields(reflect.TypeOf(base), "", nil) {
		visited[path] = true
		next := base
		fv := reflect.ValueOf(&next).Elem().FieldByIndex(index)
		switch fv.Kind() {
		case reflect.String:
			fv.SetString(fv.String() + "-changed")
		case reflect.Int, reflect.Int64, reflect.Int32:
			fv.SetInt(fv.Int() + 1)
		case reflect.Bool:
			fv.SetBool(!fv.Bool())
		case reflect.Slice:
			fv.Set(reflect.Append(fv, reflect.Zero(fv.Type().Elem())))
		default:
			t.Fatalf("%s: no mutation for kind %s — teach this test one", path, fv.Kind())
		}

		err := requireOnlyWhitelisted(base, next)
		switch {
		case hotPaths[path] && err != nil:
			t.Errorf("%s is hot-reloadable but a change to it was refused: %v", path, err)
		case !hotPaths[path] && err == nil:
			t.Errorf("%s changed and the reload was ALLOWED — it would log \"hot-reload applied\" and never take effect", path)
		case !hotPaths[path] && !strings.Contains(err.Error(), path):
			t.Errorf("%s refused, but the error doesn't name it: %v", path, err)
		}
	}

	// Guard the walker itself: these are the fields the old hand-picked
	// comparison never looked at. If they weren't visited, the loop above
	// proved nothing.
	for _, p := range []string{"mode", "role", "relay.require_auth", "relay.coord_pubkey",
		"multi_region.mode", "public.addr", "state.dir", "mesh.forward_addr", "edge_class",
		"edge_node_id", "coord_pubkey", "coord_pubkey_file", "base_domain", "http.base_domain"} {
		if !visited[p] {
			t.Errorf("walker never reached %s", p)
		}
	}
}

// leafFields maps the YAML path of every non-struct exported field under
// typ to its reflect index path.
func leafFields(typ reflect.Type, prefix string, index []int) map[string][]int {
	out := map[string][]int{}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		path := yamlName(f)
		if prefix != "" {
			path = prefix + "." + path
		}
		idx := append(append([]int(nil), index...), i)
		if f.Type.Kind() == reflect.Struct {
			for p, sub := range leafFields(f.Type, path, idx) {
				out[p] = sub
			}
			continue
		}
		out[path] = idx
	}
	return out
}

const reloadCommon = `node_label: test-edge
region: test
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
`

// standaloneEdge is a standalone edge of a coordinator, the file's tail.
const standaloneEdge = "mode: standalone\ncoord_pubkey: \"" + testCoordKey + "\"\n"

// relayCommon is reloadCommon for a relay-only node, which binds no tunnel
// listener.
const relayCommon = `node_label: test-edge
region: test
base_domain: "localtest.me"
admin:
  addr: ":9101"
log:
  level: info
  format: text
`

// platformRelay is a relay-only platform node: its relay settings are its own
// (a standalone node always requires grants, whatever relay.require_auth says).
const platformRelay = "role: relay\nrelay:\n  kind: platform\n"

// The concrete incident: an operator turns on relay grant verification,
// reloads, and reads "hot-reload applied" while the relay stays open. Each case
// changes one restart-only field in the FILE, and a base_domain change rides
// along, to prove the whitelisted part isn't half-applied either.
func TestReloadRefusesRestartOnlyFieldsFromTheFile(t *testing.T) {
	const otherKey = "yMqLvONWcTdghKQ4cwvVQ81FuXDj/0npFphl4BujbdA="
	cases := []struct {
		field         string
		before, after string
		relayOnly     bool
	}{
		{"relay.require_auth", platformRelay, platformRelay + "  require_auth: true\n", true},
		{"relay.coord_pubkey", platformRelay + "  coord_pubkey: \"" + testCoordKey + "\"\n", platformRelay + "  coord_pubkey: \"" + otherKey + "\"\n", true},
		{"relay.kind", platformRelay, strings.Replace(platformRelay, "kind: platform", "kind: self", 1), true},
		{"coord_pubkey", standaloneEdge, strings.Replace(standaloneEdge, testCoordKey, otherKey, 1), false},
		{"mode", standaloneEdge, "multi_region:\n  mode: bff-edge\n  bff_edge_addr: \"bff-edge.example.com:443\"\n", false},
		{"role", standaloneEdge + "role: edge\n", standaloneEdge + "role: both\n", false},
		{"multi_region.mode", standaloneEdge, "multi_region:\n  mode: bff-edge\n  bff_edge_addr: \"bff-edge.example.com:443\"\n", false},
		{"public.addr", standaloneEdge, standaloneEdge + "public:\n  addr: \"edge.example.com:7443\"\n", false},
		{"state.dir", standaloneEdge, standaloneEdge + "state:\n  dir: /var/lib/calabi-edge\n", false},
		{"mesh.forward_addr", standaloneEdge, standaloneEdge + "mesh:\n  forward_addr: \":7090\"\n  advertise_addr: \"edge-a.example.com:7090\"\n", false},
		{"edge_class", standaloneEdge, standaloneEdge + "edge_class: dedicated\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			hermeticEnv(t)
			common := reloadCommon
			if tc.relayOnly {
				common = relayCommon
			}
			r, ap, path := newTestReloader(t, common+tc.before)
			writeConfig(t, path, strings.Replace(common, "localtest.me", "changed.example.com", 1)+tc.after)

			err := r.reload()
			if err == nil {
				t.Fatalf("%s changed in the file and the reload was applied", tc.field)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("error doesn't name %s: %v", tc.field, err)
			}
			if n := ap.basesCount.Load(); n != 0 {
				t.Errorf("refused reload still called the applier %d time(s)", n)
			}
			if got := r.current.HTTP.BaseDomain; got != "localtest.me" {
				t.Errorf("baseline replaced by a refused reload: base_domain %q", got)
			}
		})
	}
}

// base_domain has two spellings kept equal by config.Load. Changing the
// top-level one must hot-reload just like http.base_domain does.
func TestReloadAppliesTopLevelBaseDomain(t *testing.T) {
	hermeticEnv(t)
	const tmpl = `node_label: test-edge
region: test
base_domain: "%s"
admin:
  addr: ":9101"
`
	r, ap, path := newTestReloader(t, strings.Replace(tmpl, "%s", "old.example.com", 1)+standaloneEdge)
	writeConfig(t, path, strings.Replace(tmpl, "%s", "new.example.com", 1)+standaloneEdge)

	if err := r.reload(); err != nil {
		t.Fatalf("base_domain change refused: %v", err)
	}
	if got := ap.bases[len(ap.bases)-1]; got != "new.example.com" {
		t.Errorf("base_domain applied as %q, want new.example.com", got)
	}
}

// With ANY env override in place, a base_domain-only edit must still reload.
// The boot baseline has the override applied; a reload that skipped ApplyEnv
// would see the file's value, call it a change, and refuse every reload for as
// long as the variable is set.
func TestReloadWithEnvOverridesStillAppliesBaseDomain(t *testing.T) {
	cases := map[string]string{
		"CALABI_EDGE_MODE":               "standalone", // documented in self-hosting.md
		"CALABI_EDGE_ROLE":               "both",
		"CALABI_EDGE_ADMIN_ADDR":         ":9200",
		"CALABI_EDGE_RELAY_KIND":         "platform",
		"CALABI_EDGE_RELAY_LABEL":        "hk1",
		"CALABI_EDGE_RELAY_COORD_PUBKEY": testCoordKey,
		"CALABI_EDGE_RELAY_DERP_PORT":    "3341",
		"CALABI_EDGE_RELAY_STUN_PORT":    "3479",
		"CALABI_EDGE_RELAY_REQUIRE_AUTH": "1",
		"CALABI_EDGE_COORD_PUBKEY":       testCoordKey,
		"CALABI_EDGE_COORD_PUBKEY_FILE":  "/coord/coord.pub",
	}
	// Every variable ApplyEnv reads must be exercised here.
	for _, k := range edgeEnv {
		if _, ok := cases[k]; !ok && k != "CALABI_ENV" {
			t.Fatalf("%s is read by the pipeline but not covered by this test", k)
		}
	}
	for k, v := range cases {
		t.Run(k, func(t *testing.T) {
			hermeticEnv(t)
			t.Setenv(k, v)
			yaml := formatYAML
			if k == "CALABI_EDGE_COORD_PUBKEY_FILE" {
				// A key file and an inline key are one key too many.
				yaml = func(base string) string {
					return strings.Replace(formatYAML(base), "coord_pubkey: \""+testCoordKey+"\"\n", "", 1)
				}
			}
			r, ap, path := newTestReloader(t, yaml("localtest.me"))
			writeConfig(t, path, yaml("calabi.net"))

			if err := r.reload(); err != nil {
				t.Fatalf("base_domain-only edit refused with %s=%s set: %v", k, v, err)
			}
			if got := ap.bases[len(ap.bases)-1]; got != "calabi.net" {
				t.Errorf("applied base_domain %q, want calabi.net", got)
			}
		})
	}
}

// A production edge reloads through the same checks as its boot, and a
// legitimate hot change still goes through — the guard isn't just blocking
// every reload in production.
func TestReloadRunsProductionPosture(t *testing.T) {
	hermeticEnv(t)
	t.Setenv("CALABI_ENV", "production")
	r, ap, path := newTestReloader(t, formatYAML("localtest.me"))
	writeConfig(t, path, formatYAML("calabi.net"))
	if err := r.reload(); err != nil {
		t.Fatalf("base_domain change refused in production: %v", err)
	}
	if n := ap.basesCount.Load(); n != 1 {
		t.Errorf("applier called %d times, want 1", n)
	}
}

// A reload that drops the coordinator's key would leave the edge with no way
// to accept a device. It is refused like the same file at boot, and the running
// key stays — otherwise one bad save locks every device out until someone
// notices.
func TestReloadRefusesDroppingTheCoordinatorKey(t *testing.T) {
	hermeticEnv(t)
	r, ap, path := newTestReloader(t, formatYAML("localtest.me"))
	writeConfig(t, path, strings.Replace(formatYAML("localtest.me"), "coord_pubkey: \""+testCoordKey+"\"\n", "", 1))
	err := r.reload()
	if err == nil {
		t.Fatal("reload left a standalone edge with no coordinator key")
	}
	if !strings.Contains(err.Error(), "coordinator's public key") {
		t.Errorf("error doesn't say why: %v", err)
	}
	if n := ap.basesCount.Load(); n != 0 {
		t.Errorf("applier called %d times, want 0", n)
	}
	if got := r.current.CoordPubKey; got != testCoordKey {
		t.Errorf("running coordinator key is %q after a refused reload", got)
	}
}
