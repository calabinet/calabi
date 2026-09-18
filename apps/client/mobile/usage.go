package mobile

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/calabi/calabi/apps/client/internal/creds"
)

// usageOverview is GET /v1/usage/overview: this month's traffic against the cap,
// the last seven days, and device seats — the settings screen's usage card.
//
// It is assembled here rather than in each app because the arithmetic is easy to
// get subtly wrong and both phone apps need the same answer: which bytes count
// toward the cap, what a zero limit means, and whose devices a member's seat
// count covers. The rules are the web console's overview (web/console
// src/pages/Usage.tsx); a section whose upstream failed is left out, not zeroed.
type usageOverview struct {
	// Plan is the org's plan code (free, basic, ...); "" when unknown.
	Plan    string      `json:"plan"`
	Month   *monthUsage `json:"month,omitempty"`
	Days    []dayUsage  `json:"days,omitempty"`
	Devices *seatUsage  `json:"devices,omitempty"`
}

type monthUsage struct {
	// UsedBytes is what counts toward the cap: platform tunnel + platform relay.
	UsedBytes int64 `json:"used_bytes"`
	// LimitBytes is the cap: > 0 a cap, -1 unlimited, 0 unknown (quota-svc did
	// not answer — never to be shown as unlimited).
	LimitBytes  int64 `json:"limit_bytes"`
	TunnelBytes int64 `json:"tunnel_bytes"`
	RelayBytes  int64 `json:"relay_bytes"`
	// SelfHostedBytes ran through the org's own nodes and does not count.
	SelfHostedBytes int64 `json:"self_hosted_bytes"`
	// From and To bound the billing month, which is a UTC calendar month.
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// dayUsage is one of the last seven days in the viewer's time zone, oldest
// first, the last one being today so far.
type dayUsage struct {
	Start string `json:"start"`
	Bytes int64  `json:"bytes"`
}

type seatUsage struct {
	// Used counts active devices; a disabled one frees its seat.
	Used     int64 `json:"used"`
	Disabled int64 `json:"disabled"`
	// Limit: > 0 a cap, -1 unlimited, 0 the plan has no meshnet.
	Limit int64 `json:"limit"`
	// Own: the counts cover only the caller's devices and Limit is their own
	// cap. True for everyone but an org owner or admin.
	Own bool `json:"own"`
}

func (c *Core) handleUsageOverview(w http.ResponseWriter, r *http.Request) {
	// The app's IANA zone. Without one the days would be UTC days ending
	// yesterday, a different series altogether (metering-svc GetUsageHistory).
	tz := r.URL.Query().Get("tz")
	if tz == "" {
		tz = "UTC"
	}
	daily := "/v1/usage/daily?" + url.Values{"n": {"7"}, "tz": {tz}}.Encode()
	paths := []string{"/v1/account/me", "/v1/usage/current", daily, "/v1/mesh/usage", "/v1/mesh/nodes"}
	got := c.fetchAll(r.Context(), paths)

	me := got[0]
	if me.status == http.StatusUnauthorized {
		writeRaw(w, me.status, me.body)
		return
	}
	var account struct {
		User struct {
			ID int64 `json:"id"`
		} `json:"user"`
		Role string `json:"role"`
		Plan struct {
			Code string `json:"code"`
		} `json:"plan"`
		MemberQuotas map[string]json.RawMessage `json:"member_quotas"`
	}
	haveAccount := me.ok() && json.Unmarshal(me.body, &account) == nil
	out := usageOverview{Plan: account.Plan.Code}

	var cur struct {
		PlatformBytes      int64  `json:"platform_bytes_total"`
		PlatformRelayBytes int64  `json:"platform_relay_bytes_total"`
		SelfHostedBytes    int64  `json:"self_hosted_bytes_total"`
		SelfHostedRelay    int64  `json:"self_hosted_relay_bytes_total"`
		LimitMB            int64  `json:"limit_mb"`
		WindowFrom         string `json:"window_from"`
		WindowTo           string `json:"window_to"`
	}
	if got[1].ok() && json.Unmarshal(got[1].body, &cur) == nil {
		m := &monthUsage{
			UsedBytes:       cur.PlatformBytes + cur.PlatformRelayBytes,
			TunnelBytes:     cur.PlatformBytes,
			RelayBytes:      cur.PlatformRelayBytes,
			SelfHostedBytes: cur.SelfHostedBytes + cur.SelfHostedRelay,
			From:            cur.WindowFrom,
			To:              cur.WindowTo,
		}
		switch {
		case cur.LimitMB > 0:
			m.LimitBytes = cur.LimitMB << 20
		case cur.LimitMB < 0:
			m.LimitBytes = -1
		}
		out.Month = m
	}

	var days struct {
		Buckets []struct {
			TS    string `json:"ts"`
			Bytes int64  `json:"bytes_total"`
		} `json:"buckets"`
	}
	if got[2].ok() && json.Unmarshal(got[2].body, &days) == nil && len(days.Buckets) > 0 {
		for _, b := range days.Buckets {
			out.Days = append(out.Days, dayUsage{Start: b.TS, Bytes: b.Bytes})
		}
		// The API's order is not part of its contract.
		sort.Slice(out.Days, func(i, j int) bool { return instant(out.Days[i].Start).Before(instant(out.Days[j].Start)) })
	}

	var seats struct {
		Used     int64 `json:"seats_used"`
		Disabled int64 `json:"seats_disabled"`
		Limit    int64 `json:"seats_limit"`
	}
	haveSeats := got[3].ok() && json.Unmarshal(got[3].body, &seats) == nil
	manager := account.Role == "owner" || account.Role == "admin"
	switch {
	case haveSeats && haveAccount && manager:
		out.Devices = &seatUsage{Used: seats.Used, Disabled: seats.Disabled, Limit: seats.Limit}
	case haveSeats && haveAccount && account.User.ID > 0:
		// The seat figures are the org's; a member reads their own devices
		// against their own cap. Devices with no owner count for nobody, as
		// quota-svc counts them.
		var nodes struct {
			Items []struct {
				Owner    int64 `json:"owner_user_id"`
				Disabled bool  `json:"disabled"`
			} `json:"items"`
		}
		if got[4].ok() && json.Unmarshal(got[4].body, &nodes) == nil {
			d := &seatUsage{Limit: seats.Limit, Own: true}
			for _, n := range nodes.Items {
				if n.Owner != account.User.ID {
					continue
				}
				if n.Disabled {
					d.Disabled++
				} else {
					d.Used++
				}
			}
			if v, err := strconv.ParseInt(string(account.MemberQuotas["max_mesh_nodes"]), 10, 64); err == nil {
				d.Limit = v
			}
			out.Devices = d
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// fetched is one control-plane answer; status 0 means the request failed.
type fetched struct {
	status int
	body   []byte
}

func (f fetched) ok() bool { return f.status == http.StatusOK }

// fetchAll GETs the paths concurrently as the signed-in user. An expired access
// token is renewed once for all of them (creds.RefreshSession serializes the
// exchange), not once each.
func (c *Core) fetchAll(ctx context.Context, paths []string) []fetched {
	out := make([]fetched, len(paths))
	if cfg, _ := creds.Load(); cfg == nil || cfg.AccessToken == "" {
		for i := range out {
			out[i] = fetched{status: http.StatusUnauthorized, body: []byte(`{"error":"not signed in"}`)}
		}
		return out
	}
	var wg sync.WaitGroup
	for i, p := range paths {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status, body, err := c.bffAuthed(ctx, http.MethodGet, p, nil)
			if err != nil {
				c.logger.Debug("usage: upstream failed", "path", p, "err", err)
				return
			}
			out[i] = fetched{status: status, body: body}
		}()
	}
	wg.Wait()
	return out
}

func instant(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}
