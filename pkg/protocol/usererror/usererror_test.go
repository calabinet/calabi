package usererror

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMessage(t *testing.T) {
	for _, tc := range []struct {
		name               string
		status             int
		raw, key, contains string
	}{
		{"unavailable", 503, "rpc error: code = Unavailable desc = transport: dial tcp 10.0.0.1:7001: connection refused", "unavailable", "temporarily unavailable"},
		{"legacy status", 500, "request: rpc error: code = DeadlineExceeded desc = context deadline exceeded", "timeout", "too long"},
		{"database", 500, "rpc error: code = Internal desc = pq: secret database connection", "internal", "contact support"},
		{"credentials", 401, "rpc error: code = Unauthenticated desc = invalid credentials", "invalidCredentials", "password is incorrect"},
		{"activation", 403, "rpc error: code = PermissionDenied desc = email not verified", "emailNotVerified", "verify your email"},
		{"business detail", 400, "rpc error: code = InvalidArgument desc = domain must belong to your organization", "business.domainUnverified", "verify this domain"},
		{"nested", 400, "rpc error: code = InvalidArgument desc = rpc error: code = Internal desc = pq: secret", "internal", "contact support"},
		{"json", 400, "decode body: json: unknown field password_secret", "business.invalidBody", "Check the form"},
		{"unsupported", 501, "unknown upstream method", "unsupported", "up to date"},
		{"cancelled", 499, "rpc error: code = Canceled desc = context canceled", "cancelled", "cancelled"},
		{"malformed", 503, "rpc error: code = Unavailable", "unavailable", "temporarily unavailable"},
		{"empty", 403, "", "forbidden", "permission"},
		{"legacy Chinese", 400, "赠送时长必须大于 0 天", "invalid", "check the information"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg, key := Message(tc.status, tc.raw)
			if key != tc.key || !strings.Contains(msg, tc.contains) {
				t.Fatalf("got (%q, %q)", msg, key)
			}
			for _, secret := range []string{"rpc error", "10.0.0.1", "pq:", "password_secret"} {
				if strings.Contains(msg, secret) {
					t.Fatalf("leaked %q in %q", secret, msg)
				}
			}
			if next, _ := Message(tc.status, msg); next != msg {
				t.Fatalf("not idempotent: %q => %q", msg, next)
			}
		})
	}
}

func TestProxyEnvelope(t *testing.T) {
	input := []byte(`{"error":"rpc error: code = Internal desc = pq: credentials","code":"save_failed","value":"keep","hint":"One tunnel is already disabled."}`)
	var got map[string]any
	if err := json.Unmarshal(JSON(500, input), &got); err != nil {
		t.Fatal(err)
	}
	if got["code"] != "save_failed" || got["value"] != "keep" || got["hint"] != "One tunnel is already disabled." || got["error_key"] != "internal" {
		t.Fatalf("lost envelope fields: %v", got)
	}
	if strings.Contains(got["error"].(string), "credentials") {
		t.Fatal("leaked diagnostics")
	}
	if string(JSON(200, input)) != string(input) {
		t.Fatal("changed a successful response")
	}
	for _, input := range []string{"<html>nginx 10.0.0.1</html>", "", `null`, `{"message":"internal"}`} {
		out := JSON(502, []byte(input))
		if !json.Valid(out) || !strings.Contains(string(out), `"error_key":"unavailable"`) {
			t.Fatalf("bad proxy fallback: %s", out)
		}
	}
}
