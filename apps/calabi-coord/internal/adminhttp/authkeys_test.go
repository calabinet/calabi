package adminhttp_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/adminhttp"
	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
)

func keyServer(t *testing.T, withKeys bool) *httptest.Server {
	t.Helper()
	coord := newContractCoord()
	if withKeys {
		coord.AuthKeys = core.NewMemAuthKeyStore()
	}
	coord.ListenerTLS = core.ListenerTLS{Mode: "self-signed", Pin: "sha256:" + strings.Repeat("ab", 32)}
	srv := httptest.NewServer(adminhttp.New(coord, core.NewNotifier(), coord.Logger))
	t.Cleanup(srv.Close)
	return srv
}

func call(t *testing.T, method, url, body string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// With no body, a key is what an invite should be: one device, one day.
func TestCreateAuthKeyDefaults(t *testing.T) {
	srv := keyServer(t, true)
	code, k := call(t, "POST", srv.URL+"/admin/meshnets/1/authkeys", "")
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, k)
	}
	key, _ := k["key"].(string)
	if !strings.HasPrefix(key, core.AuthKeyPrefix) || k["max_uses"].(float64) != 1 {
		t.Fatalf("created %v", k)
	}
	exp := time.UnixMilli(int64(k["expires_at_ms"].(float64)))
	if d := time.Until(exp); d < 23*time.Hour || d > 25*time.Hour {
		t.Fatalf("expires in %v, want about a day", d)
	}
	// The list never carries the key itself.
	_, list := call(t, "GET", srv.URL+"/admin/meshnets/1/authkeys", "")
	items := list["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["key"] != nil {
		t.Fatalf("list: %v", list)
	}
}

func TestCreateAuthKeyRefusesWhatItCannotMean(t *testing.T) {
	srv := keyServer(t, true)
	for _, body := range []string{
		`{"max_uses": 0}`,
		`{"max_uses": -1}`,
		`{"reusable": true, "max_uses": 3}`,
		`{"expires_in_seconds": 0}`,
		`{"expires_in_seconds": -5}`,
		`{"no_expiry": true, "expires_in_seconds": 60}`,
		`{"expires_in_seconds": 999999999999}`,
		`{"expires_in_seconds": 18446744074}`, // ×1e9 wraps a Duration to under a second
		`{"tags": ["laptop"]}`,
		`{"tags": ["tag:"]}`,
		`not json`,
	} {
		if code, out := call(t, "POST", srv.URL+"/admin/meshnets/1/authkeys", body); code != http.StatusBadRequest {
			t.Errorf("%s: %d %v, want 400", body, code, out)
		}
	}
	// And what it can.
	code, k := call(t, "POST", srv.URL+"/admin/meshnets/1/authkeys", `{"reusable": true, "no_expiry": true, "tags": ["tag:server"], "note": "rack"}`)
	if code != http.StatusCreated || k["max_uses"].(float64) != 0 || k["expires_at_ms"] != nil || k["note"] != "rack" {
		t.Fatalf("reusable, never expiring: %d %v", code, k)
	}
}

func TestRevokeAuthKeyIsPerMeshnet(t *testing.T) {
	srv := keyServer(t, true)
	_, k := call(t, "POST", srv.URL+"/admin/meshnets/1/authkeys", "")
	id := itoa(int64(k["id"].(float64)))
	if code, _ := call(t, "DELETE", srv.URL+"/admin/meshnets/2/authkeys/"+id, ""); code != http.StatusNotFound {
		t.Fatalf("revoke from another meshnet: %d", code)
	}
	if code, _ := call(t, "DELETE", srv.URL+"/admin/meshnets/1/authkeys/"+id, ""); code != http.StatusNoContent {
		t.Fatalf("revoke: %d", code)
	}
	_, list := call(t, "GET", srv.URL+"/admin/meshnets/1/authkeys", "")
	if list["items"].([]any)[0].(map[string]any)["revoked_at_ms"] == nil {
		t.Fatalf("not shown revoked: %v", list)
	}
}

// A coordinator whose credentials come from an identity service mints nothing.
func TestAuthKeysAbsentOnAnIdentityBackedCoordinator(t *testing.T) {
	srv := keyServer(t, false)
	for _, rq := range [][2]string{{"GET", "/admin/meshnets/1/authkeys"}, {"POST", "/admin/meshnets/1/authkeys"}, {"DELETE", "/admin/meshnets/1/authkeys/1"}} {
		if code, _ := call(t, rq[0], srv.URL+rq[1], ""); code != http.StatusNotFound {
			t.Errorf("%s %s: %d, want 404", rq[0], rq[1], code)
		}
	}
}

func TestListenerTLSIsReported(t *testing.T) {
	srv := keyServer(t, true)
	code, out := call(t, "GET", srv.URL+"/admin/tls", "")
	if code != http.StatusOK || out["mode"] != "self-signed" || !strings.HasPrefix(out["pin"].(string), "sha256:") {
		t.Fatalf("GET /admin/tls: %d %v", code, out)
	}
}
