package statusapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calabinet/calabi/apps/client/internal/creds"
)

// The exit device is chosen by name among the organization's devices. Another
// organization's device of that name is someone else's machine, so moving to
// another organization — by switching, or by signing out — forgets it. A switch
// to the organization it is in, or one the control plane refuses, keeps it.
func TestTheExitDeviceStaysWithItsOrganization(t *testing.T) {
	tok := isolateCreds(t)
	t.Setenv("CALABI_API_KEY", "")
	t.Setenv("CALABI_TOKEN", "")
	bff := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/orgs/switch":
			var in struct {
				TargetOrgID int64 `json:"target_org_id"`
			}
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &in)
			if in.TargetOrgID == 13 {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"not a member of this organization"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "jwt-new", "refresh_token": "rt-new", "active_org_id": in.TargetOrgID})
		case "/v1/auth/logout":
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer bff.Close()

	var switched, loggedOut int
	s := New(nil, Config{BFFConsoleURL: bff.URL,
		OnOrgSwitched: func() { switched++ },
		OnLogout:      func() { loggedOut++ },
	})
	mux := http.NewServeMux()
	s.Register(mux)
	post := func(path, body string) int {
		t.Helper()
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		req.Header.Set("X-Local-Token", tok)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr.Code
	}
	exit := func() string {
		c, _ := creds.Load()
		if c == nil {
			return ""
		}
		return c.MeshExitNode
	}
	signedInWithExit := func() {
		t.Helper()
		if err := creds.Save(&creds.Config{AccessToken: "jwt", RefreshToken: "rt", ActiveOrgID: 7, MeshExitNode: "home-server"}); err != nil {
			t.Fatal(err)
		}
	}

	signedInWithExit()
	if code := post("/v1/orgs/switch", `{"target_org_id":7}`); code != http.StatusOK {
		t.Fatalf("switch to the same organization = %d", code)
	}
	if got := exit(); got != "home-server" {
		t.Fatalf("after switching to the organization it is in, exit = %q; want it kept", got)
	}
	if code := post("/v1/orgs/switch", `{"target_org_id":13}`); code != http.StatusForbidden {
		t.Fatalf("a refused switch = %d, want 403", code)
	}
	if got := exit(); got != "home-server" {
		t.Fatalf("after a refused switch, exit = %q; want it kept", got)
	}
	if code := post("/v1/orgs/switch", `{"target_org_id":9}`); code != http.StatusOK {
		t.Fatalf("switch = %d", code)
	}
	if got := exit(); got != "" {
		t.Fatalf("after switching organization, exit = %q; want none", got)
	}
	if switched != 2 {
		t.Fatalf("OnOrgSwitched ran %d times, want 2 (the running mesh takes the exit from creds there)", switched)
	}

	signedInWithExit()
	if code := post("/v1/auth/logout", ""); code != http.StatusOK {
		t.Fatalf("logout = %d", code)
	}
	if got := exit(); got != "" {
		t.Fatalf("after signing out, exit = %q; want none", got)
	}
	if loggedOut != 1 {
		t.Fatalf("OnLogout ran %d times, want 1", loggedOut)
	}
}
