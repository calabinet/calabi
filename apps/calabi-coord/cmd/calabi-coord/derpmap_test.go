package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
)

func TestReadDERPMapFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "derp.json")
	if err := os.WriteFile(path, []byte(`{
		"home_region": "sgp",
		"regions": [
			{"code":"lax","nodes":[{"host_name":"derp-lax.example.net","derp_port":3340,"stun_port":3478}]},
			{"code":"sgp","nodes":[{"host_name":"derp-sgp.example.net","derp_port":3340,"stun_port":3478}]}
		]
	}`), 0o600); err != nil {
		t.Fatal(err)
	}

	m, home, err := readDERPMapFile(path, "")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(m.Regions) != 2 || m.Regions[0].Code != "lax" || m.Regions[1].Nodes[0].HostName != "derp-sgp.example.net" {
		t.Fatalf("regions parsed wrong: %+v", m.Regions)
	}
	if n := m.Regions[0].Nodes[0]; n.DERPPort != 3340 || n.STUNPort != 3478 {
		t.Fatalf("ports parsed wrong: %+v", n)
	}
	if home != "sgp" { // file's home_region honored (it names a region in the map)
		t.Fatalf("home = %q, want sgp", home)
	}
}

// defaultHome: file home wins, then env, then the first region; a home naming a
// region absent from the map is ignored in favor of a real one.
func TestDefaultHomeResolution(t *testing.T) {
	m := core.DERPMap{Regions: []core.DERPRegion{{Code: "lax"}, {Code: "sgp"}}}
	cases := []struct{ file, env, want string }{
		{"sgp", "", "sgp"},    // file wins
		{"", "sgp", "sgp"},    // env when no file home
		{"", "", "lax"},       // first region when neither
		{"zzz", "", "lax"},    // file names an absent region -> first
		{"zzz", "sgp", "sgp"}, // fall through to a valid env home
	}
	for _, c := range cases {
		if got := defaultHome(c.file, c.env, m); got != c.want {
			t.Errorf("defaultHome(%q,%q) = %q, want %q", c.file, c.env, got, c.want)
		}
	}
	if got := defaultHome("", "", core.DERPMap{}); got != "" {
		t.Errorf("empty map home = %q, want empty", got)
	}
}

func TestSingleRegionMap(t *testing.T) {
	m, home, err := singleRegionMap("derp-lax.example.net:3340", "lax", "3478")
	if err != nil {
		t.Fatalf("single: %v", err)
	}
	if home != "lax" || len(m.Regions) != 1 || m.Regions[0].Code != "lax" {
		t.Fatalf("region/home wrong: home=%q regions=%+v", home, m.Regions)
	}
	n := m.Regions[0].Nodes[0]
	if n.HostName != "derp-lax.example.net" || n.DERPPort != 3340 || n.STUNPort != 3478 {
		t.Fatalf("node parsed wrong: %+v", n)
	}

	// Region defaults to "default"; STUN port omitted stays 0 (honest — no STUN yet).
	m2, home2, err := singleRegionMap("relay.example.net:3340", "", "")
	if err != nil {
		t.Fatalf("single default: %v", err)
	}
	if home2 != "default" || m2.Regions[0].Nodes[0].STUNPort != 0 {
		t.Fatalf("defaults wrong: home=%q stun=%d", home2, m2.Regions[0].Nodes[0].STUNPort)
	}

	for _, bad := range []string{"no-port", "host:0", "host:notaport", ":3340"} {
		if _, _, err := singleRegionMap(bad, "lax", ""); err == nil {
			t.Errorf("singleRegionMap(%q): expected error, got nil", bad)
		}
	}
}

func TestReadDERPMapFileRejectsBad(t *testing.T) {
	dir := t.TempDir()
	bad := map[string]string{
		"no-regions": `{"regions":[]}`,
		"empty-code": `{"regions":[{"code":"","nodes":[]}]}`,
		"no-host":    `{"regions":[{"code":"lax","nodes":[{"derp_port":3340}]}]}`,
		"no-port":    `{"regions":[{"code":"lax","nodes":[{"host_name":"h"}]}]}`,
		"bad-json":   `{not json`,
	}
	for name, body := range bad {
		p := filepath.Join(dir, name+".json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := readDERPMapFile(p, ""); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
	if _, _, err := readDERPMapFile(filepath.Join(dir, "missing.json"), ""); err == nil {
		t.Error("missing file: expected error, got nil")
	}
}
