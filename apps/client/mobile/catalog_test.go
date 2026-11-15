package mobile

import (
	"context"
	"encoding/json"
	"github.com/calabinet/calabi/apps/client/internal/creds"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMobileCatalogLoginSwitchStartupAndFailure(t *testing.T) {
	bff := &fakeBFF{}
	var reports []map[string]string
	fail := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/clients/register" {
			bff.ServeHTTP(w, r)
			return
		}
		var report map[string]string
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			t.Error(err)
		}
		reports = append(reports, report)
		if r.Header.Get("Authorization") != "Bearer "+bff.currentAccess() {
			t.Error("wrong registration identity")
		}
		if fail {
			w.WriteHeader(503)
			return
		}
		_, _ = w.Write([]byte(`{"device_id":27}`))
	}))
	defer srv.Close()
	c := newTestCoreAt(t, srv.URL, &fakePlatform{})
	c.cfg.AppVersion = "3.1.1"
	old := CoreVersion
	CoreVersion = "2.8.0"
	defer func() { CoreVersion = old }()
	signIn(t, c)
	if len(reports) != 1 || reports[0]["client_type"] != "mobile" || reports[0]["app_version"] != "3.1.1" || reports[0]["core_version"] != "2.8.0" {
		t.Fatalf("login report: %v", reports)
	}
	fp := reports[0]["fingerprint"]
	if fp == "" {
		t.Fatal("no stable fingerprint")
	}
	if code, _ := call(t, c, "POST", "/v1/orgs/switch", `{"target_org_id":9}`); code != 200 {
		t.Fatalf("switch: %d", code)
	}
	cfg, _ := creds.Load()
	if cfg.DeviceID != 27 || cfg.ActiveOrgID != 9 || cfg.Fingerprint != fp {
		t.Fatalf("saved registration: %+v", cfg)
	}
	raw, _ := json.Marshal(c.cfg)
	if _, err := New(string(raw), &fakePlatform{}); err != nil {
		t.Fatal(err)
	}
	if len(reports) != 3 || reports[2]["fingerprint"] != fp {
		t.Fatalf("startup registration: %v", reports)
	}
	fail = true
	if code, _ := call(t, c, "POST", "/v1/orgs/switch", `{"target_org_id":10}`); code != 200 {
		t.Fatalf("catalog outage blocked switch: %d", code)
	}
	if err := c.registerCatalog(context.Background()); err == nil {
		t.Fatal("expected catalog error")
	}
	if code, _ := call(t, c, "POST", "/v1/auth/logout", ""); code != 200 {
		t.Fatal(code)
	}
	count := len(reports)
	c.reportCatalog(context.Background())
	if len(reports) != count {
		t.Fatal("reported a signed-out device")
	}
	signIn(t, c)
	count = len(reports)
	if err := c.saveProfile(&profile{Server: "selfhosted.example:9443"}); err != nil {
		t.Fatal(err)
	}
	c.reportCatalog(context.Background())
	if len(reports) != count {
		t.Fatal("self-hosted device reported to platform")
	}
}

func TestMobileCatalogLateResponseDoesNotOverwriteNewIdentity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fresh := &creds.Config{AccessToken: "new-token", Fingerprint: "new-install", DeviceID: 99, ActiveOrgID: 9}
		fresh.User.ID = 9
		if err := creds.Save(fresh); err != nil {
			t.Error(err)
		}
		_, _ = w.Write([]byte(`{"device_id":27}`))
	}))
	defer srv.Close()
	c := newTestCoreAt(t, srv.URL, &fakePlatform{})
	cfg := &creds.Config{AccessToken: "old-token", Fingerprint: "old-install", ActiveOrgID: 7}
	cfg.User.ID = 7
	if err := creds.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if err := c.registerCatalog(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := creds.Load()
	if err != nil || got.User.ID != 9 || got.DeviceID != 99 || got.AccessToken != "new-token" || got.ActiveOrgID != 9 {
		t.Fatalf("late report changed new identity: %+v %v", got, err)
	}
}
