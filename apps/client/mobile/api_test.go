package mobile

import (
	"net/http"
	"strings"
	"testing"

	"github.com/calabi/calabi/apps/client/internal/creds"
)

func TestLoginKeepsTheSession(t *testing.T) {
	bff := &fakeBFF{}
	c := newTestCore(t, bff, &fakePlatform{})

	if _, st := call(t, c, "GET", "/v1/state", ""); st["signed_in"] != false {
		t.Fatalf("state before login = %v", st)
	}
	signIn(t, c)
	if bff.lastLogin["identifier"] != "ada@example.com" || bff.lastLogin["prefer_personal_org"] != true {
		t.Errorf("login sent %v; want the email as identifier and prefer_personal_org", bff.lastLogin)
	}
	_, st := call(t, c, "GET", "/v1/state", "")
	if st["signed_in"] != true || st["email"] != "ada@example.com" || st["active_org_id"] != float64(7) {
		t.Fatalf("state after login = %v", st)
	}
	cfg, _ := creds.Load()
	if cfg == nil || cfg.AccessToken != "jwt-1" || cfg.RefreshToken != "rt-1" {
		t.Fatalf("saved session = %+v", cfg)
	}
}

// The app tells "wrong password" from "two-step code required" by the control
// plane's own answer, so a failed login passes it through untouched.
func TestLoginFailureIsTheControlPlanesAnswer(t *testing.T) {
	c := newTestCore(t, &fakeBFF{}, &fakePlatform{})
	code, body := call(t, c, "POST", "/v1/auth/login", `{"email":"ada@example.com","password":"nope"}`)
	if code != http.StatusUnauthorized || body["error"] != "invalid credentials" {
		t.Fatalf("login = %d %v, want the upstream 401 and its message", code, body)
	}
	if code, _ := call(t, c, "POST", "/v1/auth/login", `{"email":"ada@example.com"}`); code != http.StatusBadRequest {
		t.Fatalf("login without a password = %d, want 400", code)
	}
}

// An access token lives 15 minutes; a screen opened after that must renew it
// and carry on, not send the user to the sign-in screen.
func TestProxiedCallsRenewAnExpiredToken(t *testing.T) {
	bff := &fakeBFF{}
	c := newTestCore(t, bff, &fakePlatform{})
	signIn(t, c)
	bff.expire()

	code, body := call(t, c, "GET", "/v1/me", "")
	if code != http.StatusOK || body["email"] != "ada@example.com" {
		t.Fatalf("GET /v1/me after expiry = %d %v, want it renewed and answered", code, body)
	}
	cfg, _ := creds.Load()
	if cfg.AccessToken != bff.currentAccess() {
		t.Fatalf("saved access token %q, control plane now accepts %q", cfg.AccessToken, bff.currentAccess())
	}
}

func TestLogoutForgetsTheSessionButNotTheEmail(t *testing.T) {
	bff := &fakeBFF{}
	c := newTestCore(t, bff, &fakePlatform{})
	signIn(t, c)

	if code, _ := call(t, c, "POST", "/v1/auth/logout", ""); code != http.StatusOK {
		t.Fatalf("logout = %d", code)
	}
	if len(bff.logouts) != 1 || bff.logouts[0] != "Bearer jwt-1" {
		t.Errorf("control plane saw logouts %v, want one with the session's token", bff.logouts)
	}
	if _, st := call(t, c, "GET", "/v1/state", ""); st["signed_in"] != false {
		t.Fatalf("state after logout = %v", st)
	}
	cfg, _ := creds.Load()
	if cfg.AccessToken != "" || cfg.RefreshToken != "" || cfg.User.Email != "ada@example.com" {
		t.Fatalf("after logout creds = %+v; want tokens gone and the email kept", cfg)
	}
	if code, _ := call(t, c, "GET", "/v1/me", ""); code != http.StatusUnauthorized {
		t.Fatalf("GET /v1/me after logout = %d, want 401", code)
	}
}

func TestSettingsDefaultsAndChanges(t *testing.T) {
	c := newTestCore(t, &fakeBFF{}, &fakePlatform{})

	_, s := call(t, c, "GET", "/v1/settings", "")
	// Phones accept peers' subnet routes unless told otherwise, and
	// take their model as the name — kept, so the name does not change later.
	if s["accept_routes"] != true || s["device_name"] != "pixel-8-pro" || s["exit_node"] != "" {
		t.Fatalf("default settings = %v", s)
	}
	if cfg, _ := creds.Load(); cfg == nil || cfg.MeshNodeName != "pixel-8-pro" {
		t.Fatalf("the default name was not saved: %+v", cfg)
	}

	code, s := call(t, c, "PUT", "/v1/settings", `{"exit_node":"home-server","accept_routes":false}`)
	if code != http.StatusOK || s["exit_node"] != "home-server" || s["accept_routes"] != false || s["device_name"] != "pixel-8-pro" {
		t.Fatalf("PUT = %d %v; want the two changes and the name untouched", code, s)
	}
	code, s = call(t, c, "PUT", "/v1/settings", `{"device_name":"Ada's Phone"}`)
	if code != http.StatusOK || s["device_name"] != "adas-phone" || s["exit_node"] != "home-server" {
		t.Fatalf("rename = %d %v", code, s)
	}
	if code, _ := call(t, c, "PUT", "/v1/settings", `{"device_name":"  "}`); code != http.StatusBadRequest {
		t.Fatalf("blank name = %d, want 400", code)
	}
}

func TestDefaultDeviceNameIsNeverShared(t *testing.T) {
	a, b := defaultDeviceName("  "), defaultDeviceName("—")
	if !strings.HasPrefix(a, "phone-") || a == b {
		t.Fatalf("unusable models named %q and %q; want distinct random names", a, b)
	}
}

// The access log is one tunnel's: the id is checked here, not spliced into the
// upstream URL as given.
func TestTunnelAccessGoesToThatTunnelOnly(t *testing.T) {
	c := newTestCore(t, &fakeBFF{}, &fakePlatform{})
	signIn(t, c)

	code, body := call(t, c, "GET", "/v1/tunnels/12/access?from=2026-09-16T00:00:00Z&limit=500", "")
	if code != http.StatusOK || body["path"] != "/v1/tunnels/12/access" || body["query"] != "from=2026-09-16T00:00:00Z&limit=500" {
		t.Fatalf("access log = %d %v, want tunnel 12's with the query kept", code, body)
	}
	for _, bad := range []string{"/v1/tunnels/0/access", "/v1/tunnels/-3/access", "/v1/tunnels/12abc/access", "/v1/tunnels/access/access"} {
		if code, body := call(t, c, "GET", bad, ""); code != http.StatusBadRequest {
			t.Errorf("GET %s = %d %v, want 400", bad, code, body)
		}
	}
	if code, body := call(t, c, "GET", "/v1/tunnels?status=enabled", ""); code != http.StatusOK || body["path"] != "/v1/tunnels" || body["query"] != "status=enabled" {
		t.Fatalf("tunnel list = %d %v", code, body)
	}
}
