package clientreg

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calabinet/calabi/apps/client/internal/creds"
)

func TestRegisterProductAndCoreVersions(t *testing.T) {
	t.Setenv("CALABI_OPENWRT_VERSION", "")
	creds.SetDataDir(t.TempDir())
	t.Cleanup(func() { creds.SetDataDir("") })
	previous := DesktopVersion
	t.Cleanup(func() { DesktopVersion = previous })
	var got registerRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = registerRequest{}
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Error("missing bearer")
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
		}
		_, _ = w.Write([]byte(`{"device_id":17}`))
	}))
	defer srv.Close()
	cfg := &creds.Config{AccessToken: "token"}
	cfg.User.ID = 7
	for _, product := range []struct{ desktopVersion, kind, appVersion string }{
		{"", "cli", "2.8.0"},
		{"3.1.0", "desktop", "3.1.0"},
	} {
		DesktopVersion = product.desktopVersion
		if err := Ensure(cfg, srv.URL, "2.8.0"); err != nil {
			t.Fatal(err)
		}
		if got.ClientType != product.kind || got.AppVersion != product.appVersion || got.CoreVersion != "2.8.0" || got.ClientVersion != "2.8.0" || cfg.DeviceID != 17 {
			t.Fatalf("request=%+v device=%d", got, cfg.DeviceID)
		}
		if err := EnsureAgent(cfg, srv.URL, "2.8.0", "token"); err != nil {
			t.Fatal(err)
		}
		if got.ClientType != product.kind || got.AppVersion != product.appVersion || got.CoreVersion != "2.8.0" {
			t.Fatalf("API key registration: %+v", got)
		}
	}
	DesktopVersion = ""
	t.Setenv("CALABI_OPENWRT_VERSION", "2.8.0~openwrtdev6-2")
	if err := EnsureAgent(cfg, srv.URL, "2.8.0", "token"); err != nil {
		t.Fatal(err)
	}
	if got.ClientType != "openwrt" || got.AppVersion != "2.8.0~openwrtdev6-2" ||
		got.CoreVersion != "2.8.0" || got.ClientVersion != got.CoreVersion || cfg.DeviceID != 17 {
		t.Fatalf("openwrt: %+v device=%d", got, cfg.DeviceID)
	}
}
