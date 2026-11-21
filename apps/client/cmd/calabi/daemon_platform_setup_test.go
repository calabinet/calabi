package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/creds"
)

func TestSocketPlatformSetup(t *testing.T) {
	dir := isolateCreds(t)
	t.Setenv("CALABI_LOCAL_TOKEN", filepath.Join(dir, "local_token"))
	token, err := creds.MintLocalToken()
	if err != nil {
		t.Fatal(err)
	}
	const key = "tk_device_test"
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/account/me" {
			t.Errorf("unexpected verification request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer "+key {
			http.Error(w, "tk_bad", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"org":{"id":42},"user":{"id":0}}`))
	}))
	defer upstream.Close()
	client := newPlatformSetupClient(upstream.URL)
	client.HTTP.Transport = upstream.Client().Transport
	h := &platformSelfHosted{socketBFF: client}
	mux := http.NewServeMux()
	h.register(mux)

	setup := func(token, key string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/platform/setup", strings.NewReader(`{"api_key":"`+key+`"}`))
		req.Header.Set("X-Local-Token", token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if strings.Contains(w.Body.String(), key) {
			t.Error("key was included in the response")
		}
		return w
	}
	if w := setup("", key); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized setup returned %d", w.Code)
	}
	if w := setup(token, "tk_bad"); w.Code != http.StatusForbidden {
		t.Fatalf("invalid key returned %d", w.Code)
	}
	before, err := creds.Load()
	if err != nil || before.APIKey != "" {
		t.Fatal("failed setup wrote a credential")
	}
	w := setup(token, key)
	if w.Code != http.StatusAccepted {
		t.Fatalf("key setup returned %d: %s", w.Code, w.Body)
	}
	select {
	case <-restartCh:
		if !takeDaemonRestart() {
			t.Fatal("no restart requested")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no restart signal")
	}
	cfg, err := creds.Load()
	if err != nil || cfg.APIKey != key || cfg.Mode != clientModePlatform || cfg.ActiveOrgID != 42 {
		t.Fatal("platform identity was not persisted")
	}
	afterRestart := &platformSelfHosted{socketBFF: client, agentMode: daemonUsesAPIKey()}
	req := httptest.NewRequest(http.MethodPost, "/v1/platform/setup", strings.NewReader(`{"api_key":"tk_replacement"}`))
	req.Header.Set("X-Local-Token", token)
	w = httptest.NewRecorder()
	afterRestart.handlePlatformSetup(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("already configured daemon returned %d", w.Code)
	}
}

func TestSocketPlatformIdentityChangedAfterRestart(t *testing.T) {
	dir := isolateCreds(t)
	t.Setenv("CALABI_LOCAL_TOKEN", filepath.Join(dir, "local_token"))
	t.Setenv("CALABI_MODE", "")
	t.Setenv("CALABI_API_KEY", "")
	t.Setenv("CALABI_TOKEN", "")
	t.Cleanup(func() { platformIdentityChange.Store(0) })
	token, err := creds.MintLocalToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := creds.Save(&creds.Config{APIKey: "tk_old", ActiveOrgID: 42, DeviceID: 7, MeshAdvertiseRoutes: []string{"192.0.2.0/24"}}); err != nil {
		t.Fatal(err)
	}
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Authorization") {
		case "Bearer tk_same":
			_, _ = w.Write([]byte(`{"org":{"id":42},"user":{"id":0}}`))
		case "Bearer tk_neworg":
			_, _ = w.Write([]byte(`{"org":{"id":43},"user":{"id":0}}`))
		default:
			http.Error(w, "refused", http.StatusUnauthorized)
		}
	}))
	defer up.Close()
	client := newPlatformSetupClient(up.URL)
	client.HTTP.Transport = up.Client().Transport
	mutate := func(op, key string, wantStatus int) {
		t.Helper()
		mux := http.NewServeMux()
		(&platformSelfHosted{socketBFF: client, agentMode: true}).register(mux)
		req := httptest.NewRequest(http.MethodPost, "/v1/platform/"+op, strings.NewReader(`{"api_key":"`+key+`"}`))
		req.Header.Set("X-Local-Token", token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != wantStatus || (key != "" && strings.Contains(w.Body.String(), key)) {
			t.Fatalf("%s returned %d", op, w.Code)
		}
	}
	load := func() *creds.Config {
		t.Helper()
		cfg, err := creds.Load()
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	restart := func() {
		t.Helper()
		select {
		case <-restartCh:
			if !takeDaemonRestart() || platformIdentityChange.Load() != 2 {
				t.Fatal("identity change did not commit")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("no restart signal")
		}
	}
	mutate("replace", "tk_refused", http.StatusForbidden)
	if load().APIKey != "tk_old" {
		t.Fatal("rejected replacement changed the saved key")
	}
	mutate("replace", "tk_same", http.StatusAccepted)
	if load().APIKey != "tk_old" {
		t.Fatal("replacement wrote before the old runtime stopped")
	}
	restart()
	if cfg := load(); cfg.APIKey != "tk_same" || cfg.DeviceID != 7 || len(cfg.MeshAdvertiseRoutes) != 1 {
		t.Fatal("same-organization replacement lost device configuration")
	}
	mutate("replace", "tk_neworg", http.StatusAccepted)
	restart()
	if cfg := load(); cfg.ActiveOrgID != 43 || cfg.DeviceID != 0 || len(cfg.MeshAdvertiseRoutes) != 0 {
		t.Fatal("replacement carried state into a different organization")
	}
	mutate("clear", "", http.StatusAccepted)
	restart()
	if cfg := load(); cfg.APIKey != "" || cfg.ActiveOrgID != 0 {
		t.Fatal("clear kept a platform identity")
	}
}
