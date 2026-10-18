// oauth_secret_test.go — the OAuth client secret is write-only here too.
//
// THE BUG. The console's security drawer never sends security.oauth.client_secret
// back: it is built for the platform, where bff-console strips the secret on the
// way out (client_secret_set instead) and fills the stored one back in on save.
// This server did neither. So on a self-hosted daemon the list handed the secret
// out in plaintext, and the first save of ANY security setting on a tunnel with
// its own OAuth config — the IP rules, a Basic auth user — wrote the oauth block
// back without it, and the tunnel's login stopped working.
//
// The pair is the same as bff-console's (oauth_secret_test.go there): the server
// stops sending it, and the server remembers it.
//
// RUN: go test ./apps/client/internal/localweb/ -run TestOAuthSecret -v
package localweb

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/calabinet/calabi/apps/client/internal/creds"
)

const (
	theSecret = "gho_sup3r_s3cret_value"
	oauthCfg  = `{"security":{"oauth":{"provider":"github","client_id":"cid","client_secret":"` + theSecret + `","allow_domains":["acme.com"]}}}`
)

// secStore is a Lister + Writer that keeps what UpdateSecurity is given, so a
// test can read back what the daemon would persist and push to the edge.
type secStore struct {
	fakeStore
}

func (s *secStore) UpdateSecurity(id int64, cfg string) error {
	for i := range s.tunnels {
		if s.tunnels[i].ID == id {
			s.tunnels[i].ConfigJSON = cfg
			return nil
		}
	}
	return ErrTunnelNotFound
}

func newSecretServer(t *testing.T, cfg string) (*secStore, func(method, path string, body []byte) *httptest.ResponseRecorder) {
	t.Helper()
	t.Setenv("CALABI_LOCAL_TOKEN", filepath.Join(t.TempDir(), "lt"))
	tok, err := creds.MintLocalToken()
	if err != nil {
		t.Fatalf("mint local token: %v", err)
	}
	store := &secStore{fakeStore{tunnels: []ConfiguredTunnel{
		{ID: 1, Name: "grafana", Type: "http", LocalAddr: "127.0.0.1:3000", ConfigJSON: cfg},
	}}}
	mux := http.NewServeMux()
	New(Config{Lister: store, Writer: store}).Register(mux)
	return store, func(method, path string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("X-Local-Token", tok)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
}

// saveBody is what the drawer sends: the config it read, with the oauth block
// rebuilt from the form — no secret, because the form never had one.
func saveBody(t *testing.T, readCfg string, mutate func(oa map[string]any)) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(readCfg), &doc); err != nil {
		t.Fatalf("read config_json is not JSON: %v\n  %s", err, readCfg)
	}
	sec := doc["security"].(map[string]any)
	oa := map[string]any{"provider": "github", "client_id": "cid", "allow_domains": []any{"acme.com"}}
	if mutate != nil {
		mutate(oa)
	}
	sec["oauth"] = oa
	sec["ip"] = map[string]any{"allow": []any{"203.0.113.0/24"}} // the edit the user actually made
	cfg, _ := json.Marshal(doc)
	body, _ := json.Marshal(map[string]string{"config_json": string(cfg)})
	return body
}

func readConfig(t *testing.T, do func(string, string, []byte) *httptest.ResponseRecorder) string {
	t.Helper()
	rec := do(http.MethodGet, "/v1/tunnels/1", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/tunnels/1 = %d %s", rec.Code, rec.Body.String())
	}
	var row remoteTunnel
	if err := json.Unmarshal(rec.Body.Bytes(), &row); err != nil {
		t.Fatalf("decode row: %v", err)
	}
	return row.ConfigJSON
}

// Reading a tunnel — the list or one row — must not hand out the credential.
func TestOAuthSecretIsNotReturnedToTheClient(t *testing.T) {
	_, do := newSecretServer(t, oauthCfg)
	for _, path := range []string{"/v1/tunnels", "/v1/tunnels/1"} {
		rec := do(http.MethodGet, path, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d %s", path, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), theSecret) {
			t.Fatalf("GET %s hands out the OAuth client secret:\n  %s", path, rec.Body.String())
		}
	}
}

// ...but the drawer still has to know one EXISTS, or it shows an empty box that
// looks like a missing setting instead of "已配置".
func TestOAuthSecretPresenceIsStillReported(t *testing.T) {
	_, do := newSecretServer(t, oauthCfg)
	if cfg := readConfig(t, do); !strings.Contains(cfg, `"client_secret_set":true`) {
		t.Fatalf("nothing says a secret is configured:\n  %s", cfg)
	}
}

// The other half, and the one that broke logins: a save that does not carry
// the secret — every save the drawer makes — must keep the stored one.
func TestOAuthSecretSurvivesASaveThatOmitsIt(t *testing.T) {
	store, do := newSecretServer(t, oauthCfg)
	rec := do(http.MethodPost, "/v1/tunnels/1/security", saveBody(t, readConfig(t, do), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("save refused: %d %s", rec.Code, rec.Body.String())
	}
	stored := store.tunnels[0].ConfigJSON
	if !strings.Contains(stored, theSecret) {
		t.Fatalf("a save that only changed the IP rules dropped the stored secret — "+
			"the tunnel just lost its login:\n  %s", stored)
	}
	if !strings.Contains(stored, "203.0.113.0/24") {
		t.Fatalf("the edit itself did not land:\n  %s", stored)
	}
	// The save's echo goes back to the same page the list does.
	if strings.Contains(rec.Body.String(), theSecret) {
		t.Fatalf("the save response hands the secret back:\n  %s", rec.Body.String())
	}
}

// The presence flag is something the server says on the way out. One sent back
// in must not be persisted: it would sit in the YAML and go to the edge.
func TestOAuthSecretFlagIsNeverStored(t *testing.T) {
	store, do := newSecretServer(t, oauthCfg)
	body := saveBody(t, readConfig(t, do), func(oa map[string]any) { oa["client_secret_set"] = true })
	if rec := do(http.MethodPost, "/v1/tunnels/1/security", body); rec.Code != http.StatusOK {
		t.Fatalf("save refused: %d %s", rec.Code, rec.Body.String())
	}
	if stored := store.tunnels[0].ConfigJSON; strings.Contains(stored, "client_secret_set") {
		t.Fatalf("the presence flag was persisted:\n  %s", stored)
	}
}

// A typed secret replaces the stored one; that is how rotation works.
func TestOAuthSecretCanStillBeChanged(t *testing.T) {
	const fresh = "gho_rotated"
	store, do := newSecretServer(t, oauthCfg)
	body := saveBody(t, readConfig(t, do), func(oa map[string]any) { oa["client_secret"] = fresh })
	if rec := do(http.MethodPost, "/v1/tunnels/1/security", body); rec.Code != http.StatusOK {
		t.Fatalf("save refused: %d %s", rec.Code, rec.Body.String())
	}
	if stored := store.tunnels[0].ConfigJSON; !strings.Contains(stored, fresh) || strings.Contains(stored, theSecret) {
		t.Fatalf("rotation did not take:\n  %s", stored)
	}
}

// Turning OAuth off must not be undone by the carry-over.
func TestOAuthSecretNotResurrectedWhenOAuthRemoved(t *testing.T) {
	store, do := newSecretServer(t, oauthCfg)
	body, _ := json.Marshal(map[string]string{"config_json": `{"security":{"ip":{"allow":["203.0.113.0/24"]}}}`})
	if rec := do(http.MethodPost, "/v1/tunnels/1/security", body); rec.Code != http.StatusOK {
		t.Fatalf("save refused: %d %s", rec.Code, rec.Body.String())
	}
	if stored := store.tunnels[0].ConfigJSON; strings.Contains(stored, "oauth") || strings.Contains(stored, theSecret) {
		t.Fatalf("OAuth was removed but came back:\n  %s", stored)
	}
}

// The backup is the exception, on purpose: import writes config_json back
// verbatim, so an export without the secret would restore a tunnel whose login
// cannot work. It is local-token gated and is a file the owner asked for.
func TestOAuthSecretKeptInConfigExport(t *testing.T) {
	_, do := newSecretServer(t, oauthCfg)
	rec := do(http.MethodGet, "/v1/config/export", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("export = %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), theSecret) {
		t.Fatalf("the backup lost the secret, so restoring it breaks the login:\n  %s", rec.Body.String())
	}
}

// The control: a tunnel with no OAuth at all goes out exactly as stored.
func TestOAuthSecretControlNonOAuthConfigUnchanged(t *testing.T) {
	const ipOnly = `{"security":{"ip":{"allow":["203.0.113.0/24"]}}}`
	_, do := newSecretServer(t, ipOnly)
	if got := readConfig(t, do); got != ipOnly {
		t.Fatalf("config_json = %q, want it passed through unchanged", got)
	}
}
