package mobile

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const usageCurrent = `{"bytes_total": 9000, "platform_bytes_total": 3000, "self_hosted_bytes_total": 6000,
	"platform_relay_bytes_total": 500, "self_hosted_relay_bytes_total": 70, "limit_mb": %d,
	"window_from": "2026-09-01T08:00:00+08:00", "window_to": "2026-10-01T08:00:00+08:00"}`

const usageDaily = `{"buckets": [
	{"ts": "2026-09-17T00:00:00+08:00", "bytes_total": 7},
	{"ts": "2026-09-15T00:00:00+08:00", "bytes_total": 5},
	{"ts": "2026-09-16T00:00:00+08:00", "bytes_total": 6}]}`

const usageNodes = `{"items": [
	{"id": 1, "owner_user_id": 42},
	{"id": 2, "owner_user_id": 42, "disabled": true},
	{"id": 3, "owner_user_id": 43},
	{"id": 4, "owner_user_id": 0}]}`

func TestUsageOverviewForAManager(t *testing.T) {
	bff := &fakeBFF{
		me:        `{"user": {"id": 42}, "role": "owner", "plan": {"code": "pro"}, "member_quotas": null}`,
		current:   fmt.Sprintf(usageCurrent, 1024),
		daily:     usageDaily,
		meshUsage: `{"seats_used": 12, "seats_disabled": 3, "seats_limit": 30}`,
		nodes:     usageNodes,
	}
	c := newTestCore(t, bff, &fakePlatform{})
	signIn(t, c)

	code, body := call(t, c, "GET", "/v1/usage/overview?tz=Asia/Tokyo", "")
	if code != http.StatusOK || body["plan"] != "pro" {
		t.Fatalf("overview = %d %v", code, body)
	}
	month := body["month"].(map[string]any)
	// Platform tunnel + platform relay count; self-hosted of either kind does not.
	if month["used_bytes"] != float64(3500) || month["tunnel_bytes"] != float64(3000) ||
		month["relay_bytes"] != float64(500) || month["self_hosted_bytes"] != float64(6070) {
		t.Errorf("month = %v", month)
	}
	if month["limit_bytes"] != float64(1<<30) {
		t.Errorf("limit_bytes = %v, want 1024 MB in bytes", month["limit_bytes"])
	}
	if q, _ := url.ParseQuery(bff.queries["/v1/usage/daily"]); q.Get("tz") != "Asia/Tokyo" || q.Get("n") != "7" {
		t.Errorf("daily asked with %q, want the viewer's zone and seven days", bff.queries["/v1/usage/daily"])
	}
	var bytes []float64
	for _, d := range body["days"].([]any) {
		bytes = append(bytes, d.(map[string]any)["bytes"].(float64))
	}
	if fmt.Sprint(bytes) != "[5 6 7]" {
		t.Errorf("days = %v, want oldest first", bytes)
	}
	devices := body["devices"].(map[string]any)
	if devices["used"] != float64(12) || devices["disabled"] != float64(3) || devices["limit"] != float64(30) || devices["own"] != false {
		t.Errorf("devices = %v, want the org's seats", devices)
	}
}

// A member reads their own devices against their own cap, not the org's.
func TestUsageOverviewForAMemberCountsTheirOwnDevices(t *testing.T) {
	bff := &fakeBFF{
		me:        `{"user": {"id": 42}, "role": "developer", "plan": {"code": "business"}, "member_quotas": {"max_mesh_nodes": 5}}`,
		current:   fmt.Sprintf(usageCurrent, -1),
		meshUsage: `{"seats_used": 12, "seats_disabled": 3, "seats_limit": 30}`,
		nodes:     usageNodes,
	}
	c := newTestCore(t, bff, &fakePlatform{})
	signIn(t, c)

	_, body := call(t, c, "GET", "/v1/usage/overview?tz=UTC", "")
	devices := body["devices"].(map[string]any)
	if devices["used"] != float64(1) || devices["disabled"] != float64(1) || devices["limit"] != float64(5) || devices["own"] != true {
		t.Errorf("devices = %v, want 1 active + 1 disabled of the member's own, cap 5", devices)
	}
	if month := body["month"].(map[string]any); month["limit_bytes"] != float64(-1) {
		t.Errorf("limit_bytes = %v, want -1 (unlimited)", month["limit_bytes"])
	}
	// No member cap set: the org's limit applies.
	bff.me = `{"user": {"id": 42}, "role": "developer", "plan": {"code": "business"}, "member_quotas": null}`
	_, body = call(t, c, "GET", "/v1/usage/overview?tz=UTC", "")
	if devices := body["devices"].(map[string]any); devices["limit"] != float64(30) {
		t.Errorf("devices = %v, want the org's cap", devices)
	}
}

// limit_mb 0 is quota-svc not answering. It must not read as unlimited, and a
// section whose upstream failed is left out rather than shown as zero.
func TestUsageOverviewLeavesOutWhatItCouldNotRead(t *testing.T) {
	bff := &fakeBFF{
		me:      `{"user": {"id": 42}, "role": "owner", "plan": {"code": "free"}}`,
		current: fmt.Sprintf(usageCurrent, 0),
	}
	c := newTestCore(t, bff, &fakePlatform{})
	signIn(t, c)

	code, body := call(t, c, "GET", "/v1/usage/overview?tz=UTC", "")
	if code != http.StatusOK {
		t.Fatalf("overview = %d %v", code, body)
	}
	if month := body["month"].(map[string]any); month["limit_bytes"] != float64(0) {
		t.Errorf("limit_bytes = %v, want 0 (unknown)", month["limit_bytes"])
	}
	if _, ok := body["days"]; ok {
		t.Errorf("days = %v, want it left out", body["days"])
	}
	if _, ok := body["devices"]; ok {
		t.Errorf("devices = %v, want it left out", body["devices"])
	}
}

// A section that failed is left out — that is the point of the test above. But
// when EVERY section failed the phone read nothing, and answering 200 with an
// overview that is empty in every field made the app draw an empty usage card:
// "I could not read this" rendered as "there is nothing here".
//
// Found on a real phone (2026-09-21) by turning its Wi-Fi off and looking at
// the settings tab: the 用量 heading with a blank space under it.
func TestUsageOverviewThatReachedNothingSaysSoInsteadOfComingBackEmpty(t *testing.T) {
	bff := &fakeBFF{
		me:        `{"user": {"id": 42}, "role": "owner", "plan": {"code": "pro"}}`,
		current:   fmt.Sprintf(usageCurrent, 1024),
		daily:     usageDaily,
		meshUsage: `{"seats_used": 12, "seats_disabled": 3, "seats_limit": 30}`,
		nodes:     usageNodes,
	}
	srv := httptest.NewServer(bff)
	c := newTestCoreAt(t, srv.URL, &fakePlatform{})
	signIn(t, c)

	// While the control plane answers, the overview is an overview.
	if code, body := call(t, c, "GET", "/v1/usage/overview?tz=UTC", ""); code != http.StatusOK || body["plan"] != "pro" {
		t.Fatalf("overview while up = %d %v", code, body)
	}

	srv.Close() // the phone loses its network

	code, body := call(t, c, "GET", "/v1/usage/overview?tz=UTC", "")
	if code != http.StatusBadGateway || body["code"] != "unreachable" {
		t.Fatalf("overview while offline = %d %v, want 502 with code unreachable", code, body)
	}
	if _, has := body["plan"]; has {
		t.Errorf("an overview came back for a phone that reached nothing: %v", body)
	}
	msg, _ := body["error"].(string)
	for _, leak := range []string{"rpc error", "transport:", "dial tcp", "connection refused", "EOF"} {
		if strings.Contains(msg, leak) {
			t.Errorf("%q leaked into the message shown to a person: %s", leak, msg)
		}
	}
}
