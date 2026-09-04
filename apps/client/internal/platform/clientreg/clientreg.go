// Package clientreg keeps the "ensure this device is registered with
// identity-svc" logic in one place so both the daemon's reconnect loop
// (after a CLI `calabi login`) and the SPA's /v1/auth/login handler
// (in statusapi) can call it without duplicating the proto + dial
// dance.
//
// Why it exists: the wizard's "客户端 (设备)" dropdown relies on
// /v1/clients to pre-fill the active device. /v1/clients reads from
// identity-svc.ListClients(user_id), which is empty until a
// RegisterClient RPC has been made for the (user, fingerprint) pair.
// Without auto-registration the dropdown shows "device #N" or
// (worse) nothing, and freshly created tunnels can't be auto-claimed
// because client_id stays 0. We solve that by always calling
// RegisterClient after a successful login, using the OS hostname as
// the default device label.
//
// Registration is idempotent on (user_id, fingerprint) — calling
// repeatedly just refreshes display_name / os_info / last_seen.
//
// rewritten to go through bff-console REST instead of dialing
// identity-svc gRPC directly. Production now only exposes bff-console
// publicly; the daemon is no longer expected to reach identity-svc.
package clientreg

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/calabi/calabi/apps/client/internal/creds"
)

// registerRequest mirrors the JSON shape bff-console expects on
// POST /v1/clients/register. The user_id is NOT in the body — the
// bff-console handler reads it from the JWT principal.
type registerRequest struct {
	Fingerprint   string `json:"fingerprint"`
	DisplayName   string `json:"display_name,omitempty"`
	OsInfo        string `json:"os_info,omitempty"`
	ClientVersion string `json:"client_version,omitempty"`
}

// registerResponse mirrors the JSON returned by bff-console.
type registerResponse struct {
	DeviceID int64 `json:"device_id"`
	// We don't need any other fields right now; bff-console returns the
	// full client metadata too but the daemon only persists the id.
}

// Ensure registers this device via bff-console.
//
//   - cfg            — loaded creds (must have UserID != 0 + a non-empty
//     AccessToken / APIKey; static-token callers without
//     either field should skip this call)
//   - bffConsoleURL  — HTTP base URL of bff-console (e.g.
//     "https://api.calabi.net" or "http://127.0.0.1:8002")
//   - version        — value sent as client_version for the catalog
//
// Errors are returned so the caller can log them but should not fail
// the surrounding operation (login still succeeds, tunnel still
// connects). Caller is expected to log + swallow.
func Ensure(cfg *creds.Config, bffConsoleURL, version string) error {
	if cfg == nil || cfg.User.ID == 0 {
		return fmt.Errorf("not logged in")
	}
	if bffConsoleURL == "" {
		return fmt.Errorf("bff-console URL not configured")
	}
	fp, err := cfg.EnsureFingerprint()
	if err != nil {
		return fmt.Errorf("fingerprint: %w", err)
	}

	label := ""
	if h, _ := os.Hostname(); h != "" {
		label = h
	}

	body, err := json.Marshal(registerRequest{
		Fingerprint:   fp,
		DisplayName:   label,
		OsInfo:        runtime.GOOS + "/" + runtime.GOARCH,
		ClientVersion: version,
	})
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	base := strings.TrimRight(bffConsoleURL, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/v1/clients/register", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	token := tokenFor(cfg)
	if token == "" {
		return fmt.Errorf("no access token in creds")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 6 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST /v1/clients/register: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("register: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var out registerResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if out.DeviceID != 0 && cfg.DeviceID != out.DeviceID {
		cfg.DeviceID = out.DeviceID
		if err := creds.Save(cfg); err != nil {
			return fmt.Errorf("save device_id: %w", err)
		}
	}
	return nil
}

// EnsureAgent registers this machine as an ORG-OWNED agent device via
// bff-console, authenticating with a long-lived API key (the service's
// CALABI_API_KEY) rather than a user login. bff-console infers the org from the
// key's principal and creates an agent row (user_id=0). The returned device_id
// is persisted to creds so the data-plane AUTH frame carries it (presence works)
// and the local :7400 console scopes its tunnel list to THIS agent.
//
//   - cfg           — loaded creds (for fingerprint + device_id persistence)
//   - bffConsoleURL — HTTP base of bff-console
//   - version       — sent as client_version
//   - apiKey        — the bearer to authenticate with (resolved API key; the
//     service's key lives in env, not creds)
//
// Errors are returned for the caller to log + swallow (registration failure
// must not break the data-plane session).
func EnsureAgent(cfg *creds.Config, bffConsoleURL, version, apiKey string) error {
	if cfg == nil {
		return fmt.Errorf("nil config")
	}
	if apiKey == "" {
		return fmt.Errorf("no api key")
	}
	if bffConsoleURL == "" {
		return fmt.Errorf("bff-console URL not configured")
	}
	fp, err := cfg.EnsureFingerprint()
	if err != nil {
		return fmt.Errorf("fingerprint: %w", err)
	}
	label := ""
	if h, _ := os.Hostname(); h != "" {
		label = h
	}
	body, err := json.Marshal(registerRequest{
		Fingerprint:   fp,
		DisplayName:   label,
		OsInfo:        runtime.GOOS + "/" + runtime.GOARCH,
		ClientVersion: version,
	})
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	base := strings.TrimRight(bffConsoleURL, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/v1/clients/register", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 6 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST /v1/clients/register: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("register agent: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out registerResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if out.DeviceID != 0 && cfg.DeviceID != out.DeviceID {
		cfg.DeviceID = out.DeviceID
		if err := creds.Save(cfg); err != nil {
			return fmt.Errorf("save device_id: %w", err)
		}
	}
	return nil
}

// tokenFor returns the bearer token to send. Prefers OAuth access token
// (rotates regularly) and falls back to the long-lived API key when set.
func tokenFor(cfg *creds.Config) string {
	if cfg.AccessToken != "" {
		return cfg.AccessToken
	}
	return cfg.APIKey
}
