package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calabinet/calabi/apps/client/internal/localweb"
	"github.com/calabinet/calabi/apps/client/internal/platform/statusapi"
	"github.com/calabinet/calabi/apps/client/internal/selfupdate"
)

func TestStandaloneConsoleKeepsProductUpdateRoutes(t *testing.T) {
	mux := http.NewServeMux()
	localweb.New(localweb.Config{}).Register(mux)
	core := selfupdate.NewAgent(&selfupdate.Updater{CurrentVersion: "2.8.0", DownloadDir: t.TempDir()}, nil)
	desktop := selfupdate.NewAgent(&selfupdate.Updater{CurrentVersion: "3.0.0", DownloadDir: t.TempDir()}, nil)
	statusapi.New(nil, statusapi.Config{Update: core, DesktopUpdate: desktop}).RegisterUpdates(mux)
	for path, version := range map[string]string{"/v1/update": "2.8.0", "/v1/update?product=desktop": "3.0.0"} {
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
		var snap selfupdate.Snapshot
		if err := json.Unmarshal(rr.Body.Bytes(), &snap); err != nil {
			t.Fatal(err)
		}
		if rr.Code != http.StatusOK || snap.Current != version {
			t.Fatalf("%s: %d %s", path, rr.Code, rr.Body.String())
		}
	}
	// Registering updater APIs must not replace the standalone account surface.
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/v1/me", nil))
	var me struct {
		Plan struct {
			Code string `json:"code"`
		} `json:"plan"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if rr.Code != http.StatusOK || me.Plan.Code != "standalone" {
		t.Fatalf("local identity changed: %d %s", rr.Code, rr.Body.String())
	}
}
