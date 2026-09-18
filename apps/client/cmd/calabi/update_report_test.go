package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calabi/calabi/apps/client/internal/creds"
	"github.com/calabi/calabi/apps/client/internal/selfupdate"
)

// The status code decides whether the agent keeps a batch or drops it. Getting
// it backwards either loses results a login would have delivered, or keeps a
// malformed batch that fails identically until the queue cap evicts it.
func TestUpdateReportKeepsWhatALaterAttemptCanDeliver(t *testing.T) {
	isolateCreds(t)
	if err := creds.Save(&creds.Config{Fingerprint: "fp_0123456789abcdef0123456789abcdef"}); err != nil {
		t.Fatal(err)
	}

	var got struct {
		Fingerprint string                   `json:"fingerprint"`
		Events      []selfupdate.UpdateEvent `json:"events"`
	}
	var auth string
	code := http.StatusNoContent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/clients/update-events" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		auth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(code)
	}))
	defer srv.Close()

	evs := []selfupdate.UpdateEvent{{AttemptID: "a1", From: "1.10.0", To: "1.11.0", Result: selfupdate.ResultStarted}}
	post := func() error { return postUpdateEvents(context.Background(), srv.Client(), srv.URL, "tk_test", evs) }

	if err := post(); err != nil {
		t.Fatalf("2xx: %v", err)
	}
	if auth != "Bearer tk_test" || got.Fingerprint == "" || len(got.Events) != 1 || got.Events[0].AttemptID != "a1" {
		t.Errorf("request = auth %q body %+v", auth, got)
	}

	for _, c := range []struct {
		code     int
		rejected bool
	}{
		{http.StatusBadRequest, true},
		{http.StatusRequestEntityTooLarge, true},
		{http.StatusUnauthorized, false},
		{http.StatusNotFound, false}, // a control plane without the endpoint yet
		{http.StatusNotImplemented, false},
		{http.StatusBadGateway, false},
	} {
		code = c.code
		err := post()
		if err == nil {
			t.Errorf("HTTP %d: no error", c.code)
			continue
		}
		if errors.Is(err, selfupdate.ErrReportRejected) != c.rejected {
			t.Errorf("HTTP %d: rejected=%v, want %v (%v)", c.code, !c.rejected, c.rejected, err)
		}
	}
}

// No fingerprint = this install never registered, so there is no device to
// attach results to. Keep them (no-credential), do not send.
func TestUpdateReportWaitsForARegisteredDevice(t *testing.T) {
	isolateCreds(t)
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer srv.Close()

	err := postUpdateEvents(context.Background(), srv.Client(), srv.URL, "tk_test", nil)
	if !errors.Is(err, selfupdate.ErrReportNoCredential) {
		t.Errorf("err = %v, want ErrReportNoCredential", err)
	}
	if called {
		t.Error("posted without a registered device")
	}
}

// Only "no credential" means "no org's rules apply". Anything else — a token
// mid-refresh, a control plane without the endpoint — must leave the cached
// policy in force, which the agent does for every error except ErrNoOrg.
func TestFetchOrgPolicy(t *testing.T) {
	code := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/org/client-update-policy" || r.Header.Get("Authorization") != "Bearer tk_test" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(code)
		_, _ = w.Write([]byte(`{"org_id":7,"min_mode":"auto","max_defer_days":3,"updated_at":"2026-09-16T10:00:00Z"}`))
	}))
	defer srv.Close()

	o, err := fetchOrgPolicy(context.Background(), srv.Client(), srv.URL, "tk_test")
	if err != nil || o.OrgID != 7 || o.MinMode != "auto" || o.MaxDeferDays == nil || *o.MaxDeferDays != 3 {
		t.Fatalf("policy = %+v, %v", o, err)
	}
	if _, err := fetchOrgPolicy(context.Background(), srv.Client(), srv.URL, ""); !errors.Is(err, selfupdate.ErrNoOrg) {
		t.Errorf("no credential: err = %v, want ErrNoOrg", err)
	}
	for _, c := range []int{http.StatusUnauthorized, http.StatusNotFound, http.StatusBadGateway} {
		code = c
		if _, err := fetchOrgPolicy(context.Background(), srv.Client(), srv.URL, "tk_test"); err == nil || errors.Is(err, selfupdate.ErrNoOrg) {
			t.Errorf("HTTP %d: err = %v, want a plain error (keep the cached policy)", c, err)
		}
	}
}
