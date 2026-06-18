package localweb

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/calabi/calabi/apps/client/internal/creds"
)

// fakeStore implements Lister + Writer for the config export/import handlers.
type fakeStore struct {
	tunnels []ConfiguredTunnel
	created []TunnelSpec
}

func (f *fakeStore) Tunnels() []ConfiguredTunnel               { return f.tunnels }
func (f *fakeStore) DeleteTunnel(int64) error                  { return nil }
func (f *fakeStore) UpdateSecurity(int64, string) error        { return nil }
func (f *fakeStore) UpdateTunnel(int64, string, string) error  { return nil }
func (f *fakeStore) CreateTunnel(spec TunnelSpec) (int64, error) {
	f.created = append(f.created, spec)
	return int64(len(f.created)), nil
}

func TestConfigExportImport(t *testing.T) {
	t.Setenv("CALABI_LOCAL_TOKEN", filepath.Join(t.TempDir(), "lt"))
	tok, err := creds.MintLocalToken()
	if err != nil {
		t.Fatalf("mint local token: %v", err)
	}

	store := &fakeStore{tunnels: []ConfiguredTunnel{
		{ID: 1, Name: "web", Type: "http", LocalAddr: "127.0.0.1:8080", Domain: "a.localtest.me", EdgeNodeID: 1},
	}}
	mux := http.NewServeMux()
	New(Config{Lister: store, Writer: store}).Register(mux)

	do := func(method, path, tokenHdr string, body []byte) *httptest.ResponseRecorder {
		var rdr *bytes.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		} else {
			rdr = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, path, rdr)
		if tokenHdr != "" {
			req.Header.Set("X-Local-Token", tokenHdr)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	// --- export ---
	rec := do(http.MethodGet, "/v1/config/export", tok, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("export status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var doc struct {
		SchemaVersion int              `json:"schema_version"`
		ExportedAt    string           `json:"exported_at"`
		Tunnels       []map[string]any `json:"tunnels"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode export: %v", err)
	}
	if doc.SchemaVersion != configSchemaVersion {
		t.Errorf("schema_version=%d want %d", doc.SchemaVersion, configSchemaVersion)
	}
	if len(doc.Tunnels) != 1 || doc.Tunnels[0]["name"] != "web" {
		t.Fatalf("exported tunnels = %+v", doc.Tunnels)
	}
	exported := rec.Body.Bytes()

	// --- export without token → 401 ---
	if r := do(http.MethodGet, "/v1/config/export", "", nil); r.Code != http.StatusUnauthorized {
		t.Errorf("export w/o token = %d, want 401", r.Code)
	}

	// --- import the exported doc → "web" already exists → SKIPPED, not duped ---
	r := do(http.MethodPost, "/v1/config/import", tok, exported)
	if r.Code != http.StatusOK {
		t.Fatalf("import status = %d, body=%s", r.Code, r.Body.String())
	}
	var res struct {
		Created int `json:"created"`
		Skipped int `json:"skipped"`
		Items   []struct {
			Name    string `json:"name"`
			Created bool   `json:"created"`
			Skipped bool   `json:"skipped"`
		} `json:"items"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode import: %v", err)
	}
	if res.Skipped != 1 || res.Created != 0 || len(store.created) != 0 {
		t.Fatalf("dedup failed: skipped=%d created=%d store=%+v", res.Skipped, res.Created, store.created)
	}
	if len(res.Items) != 1 || !res.Items[0].Skipped {
		t.Errorf("item not marked skipped: %+v", res.Items)
	}

	// --- import a NEW tunnel → created ---
	newDoc := []byte(`{"schema_version":1,"tunnels":[{"name":"api","type":"http","local_addr":"127.0.0.1:9000"}]}`)
	if r := do(http.MethodPost, "/v1/config/import", tok, newDoc); r.Code != http.StatusOK {
		t.Fatalf("new import status = %d, body=%s", r.Code, r.Body.String())
	}
	if len(store.created) != 1 || store.created[0].Name != "api" {
		t.Fatalf("new tunnel not created: %+v", store.created)
	}

	// --- dry-run of a NEW tunnel does NOT create ---
	before := len(store.created)
	dryDoc := []byte(`{"schema_version":1,"tunnels":[{"name":"db","type":"tcp","local_addr":"127.0.0.1:5432"}]}`)
	if r := do(http.MethodPost, "/v1/config/import?dry_run=1", tok, dryDoc); r.Code != http.StatusOK {
		t.Fatalf("dry-run status = %d", r.Code)
	}
	if len(store.created) != before {
		t.Errorf("dry-run created tunnels: was %d now %d", before, len(store.created))
	}
}
