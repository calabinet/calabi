package mobile

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/creds"
)

// Registration is best effort. A catalog outage must not prevent sign-in or
// mesh use. Retry on startup, sign-in, org switch and the next mesh enrollment.
func (c *Core) reportCatalog(ctx context.Context) {
	if err := c.registerCatalog(ctx); err != nil {
		c.logger.Warn("client catalog registration failed", "err", err)
	}
}

func (c *Core) registerCatalog(ctx context.Context) error {
	if c.selfHosted() != nil {
		return nil
	}
	cfg, err := creds.Load()
	if err != nil {
		return err
	}
	if cfg == nil || cfg.User.ID == 0 || cfg.AccessToken == "" {
		return nil
	}
	fp, err := cfg.EnsureFingerprint()
	if err != nil {
		return err
	}
	st := c.loadSettings()
	body, err := json.Marshal(map[string]string{
		"fingerprint": fp, "display_name": st.DeviceName,
		"os_info":     runtime.GOOS + "/" + runtime.GOARCH,
		"client_type": "mobile", "app_version": c.cfg.AppVersion,
		"core_version": CoreVersion, "client_version": CoreVersion,
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	status, response, err := c.bff(ctx, http.MethodPost, "/v1/clients/register", body, cfg.AccessToken)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("catalog HTTP %d", status)
	}
	var out struct {
		DeviceID int64 `json:"device_id"`
	}
	if err := json.Unmarshal(response, &out); err != nil {
		return err
	}
	if out.DeviceID <= 0 {
		return fmt.Errorf("catalog returned no device_id")
	}
	// Do not replace refreshed credentials, a new login or a different org.
	fresh, err := creds.Load()
	if err != nil {
		return err
	}
	if fresh != nil && fresh.User.ID == cfg.User.ID && fresh.ActiveOrgID == cfg.ActiveOrgID &&
		fresh.Fingerprint == fp && fresh.AccessToken != "" && fresh.DeviceID != out.DeviceID {
		fresh.DeviceID = out.DeviceID
		return creds.Save(fresh)
	}
	return nil
}

func (c *Core) catalogFingerprint() string {
	if c.selfHosted() != nil {
		return ""
	}
	cfg, _ := creds.Load()
	if cfg == nil {
		return ""
	}
	return cfg.Fingerprint
}
