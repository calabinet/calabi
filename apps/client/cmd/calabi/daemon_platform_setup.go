package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/creds"
	"github.com/calabinet/calabi/apps/client/internal/platform/bffclient"
)

func newPlatformSetupClient(base string) *bffclient.Client {
	client := bffclient.New(base, "")
	client.HTTP.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return client
}

func (h *platformSelfHosted) handlePlatformSetup(w http.ResponseWriter, r *http.Request) {
	h.changePlatformIdentity(w, r, false, false)
}

func (h *platformSelfHosted) handlePlatformReplace(w http.ResponseWriter, r *http.Request) {
	h.changePlatformIdentity(w, r, true, false)
}

func (h *platformSelfHosted) handlePlatformClear(w http.ResponseWriter, r *http.Request) {
	h.changePlatformIdentity(w, r, true, true)
}

var platformIdentityChange atomic.Int32

func platformIdentityManaged() bool {
	return os.Getenv("CALABI_API_KEY") == "" && os.Getenv("CALABI_TOKEN") == "" && os.Getenv("CALABI_MODE") == ""
}

func (h *platformSelfHosted) handlePlatformIdentity(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	cfg, err := creds.Load()
	if err != nil {
		shError(w, http.StatusInternalServerError, "load", "could not read the daemon credentials", nil)
		return
	}
	change := [...]string{"", "applying", "saved", "failed"}[platformIdentityChange.Load()]
	shJSON(w, http.StatusOK, map[string]any{
		"configured": h.agentMode || cfg.APIKey != "",
		"managed":    platformIdentityManaged() && (!h.agentMode || cfg.APIKey != ""),
		"org_id":     cfg.ActiveOrgID, "change": change,
	})
}

func (h *platformSelfHosted) changePlatformIdentity(w http.ResponseWriter, r *http.Request, replace, clear bool) {
	w.Header().Set("Cache-Control", "no-store")
	if !creds.CompareLocalToken(r.Header.Get("X-Local-Token")) {
		shError(w, http.StatusUnauthorized, "local_token", "local token required", nil)
		return
	}
	h.provisionMu.Lock()
	defer h.provisionMu.Unlock()
	if h.switchPending {
		shError(w, http.StatusConflict, "switching", "wait for the daemon to restart", nil)
		return
	}
	cfg, err := creds.Load()
	if err != nil {
		shError(w, http.StatusInternalServerError, "load", "could not read the daemon credentials", nil)
		return
	}
	if !platformIdentityManaged() {
		shError(w, http.StatusConflict, "identity_unmanaged", "identity is managed outside the daemon", nil)
		return
	}
	if !replace && (h.agentMode || cfg.APIKey != "" || cfg.AccessToken != "" || cfg.RefreshToken != "") {
		shError(w, http.StatusConflict, "configured", "the daemon already has an identity", nil)
		return
	}
	if replace && (!h.agentMode || cfg.APIKey == "") {
		shError(w, http.StatusConflict, "identity_unmanaged", "no saved platform API key to change", nil)
		return
	}
	if clear {
		h.commitPlatformIdentity(w, "", 0)
		return
	}
	var in struct {
		Key string `json:"api_key"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	if err := dec.Decode(&in); err != nil || dec.Decode(new(json.RawMessage)) != io.EOF {
		shError(w, http.StatusBadRequest, "bad_input", "enter an API key", nil)
		return
	}
	key := strings.TrimSpace(in.Key)
	if !strings.HasPrefix(key, "tk_") || len(key) <= len("tk_") || strings.ContainsAny(key, " \t\r\n") {
		shError(w, http.StatusBadRequest, "bad_input", "enter an API key", nil)
		return
	}
	base, err := url.Parse(h.socketBFF.BaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil {
		shError(w, http.StatusServiceUnavailable, "platform_config", "platform key verification requires an HTTPS endpoint", nil)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	client := *h.socketBFF
	client.Token = key
	var identity struct {
		Org  struct{ ID int64 } `json:"org"`
		User struct{ ID int64 } `json:"user"`
	}
	err = client.Do(ctx, http.MethodGet, "/v1/account/me", nil, &identity)
	switch {
	case bffclient.IsStatus(err, http.StatusUnauthorized), bffclient.IsStatus(err, http.StatusForbidden):
		shError(w, http.StatusForbidden, "key_refused", "the platform did not accept this API key", nil)
		return
	case err != nil || identity.Org.ID <= 0 || identity.User.ID != 0:
		shError(w, http.StatusBadGateway, "key_unverified", "could not verify the platform API key", nil)
		return
	}
	h.commitPlatformIdentity(w, key, identity.Org.ID)
}

func (h *platformSelfHosted) commitPlatformIdentity(w http.ResponseWriter, key string, orgID int64) {
	h.switchPending = true
	platformIdentityChange.Store(1)
	// Save after the old runtime releases its session and stops writing its
	// credentials. An unsuccessful atomic save leaves the old identity usable.
	requestDaemonRestartWithCommit(300*time.Millisecond, func() {
		cfg, err := creds.Load()
		if err == nil {
			deviceID := cfg.DeviceID
			if orgID == 0 || orgID != cfg.ActiveOrgID {
				cfg = &creds.Config{}
				deviceID = 0
			}
			cfg.ClearAuth()
			cfg.Mode, cfg.APIKey, cfg.ActiveOrgID, cfg.DeviceID = clientModePlatform, key, orgID, deviceID
			err = creds.Save(cfg)
		}
		if err != nil {
			platformIdentityChange.Store(3)
			return
		}
		platformIdentityChange.Store(2)
	})
	shJSON(w, http.StatusAccepted, map[string]any{"switching": true})
}
