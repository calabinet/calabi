package usererror

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBusinessCatalogRoundTrips(t *testing.T) {
	values := map[string]string{"resource": "device", "minimum": "8", "limit": "3", "current": "2", "devices": "1", "tunnels": "2", "keys": "3", "port": "8080", "domain": "app.example.com", "available": "$4.00", "credit": "$1.00", "balance": "$3.00", "required": "$8.00"}
	for key := range businessCatalog.Messages {
		t.Run(key, func(t *testing.T) {
			text, ok := Format(key, values)
			if !ok || text == "" || strings.Contains(text, "{{") {
				t.Fatalf("bad format: %q", text)
			}
			got, resolved, args, ok := Business(text, "")
			if !ok || resolved != "business."+key || got != text {
				t.Fatalf("cannot recognize canonical text: (%q,%q,%v)", got, resolved, ok)
			}
			body := Body(400, map[string]any{"error": text, "error_key": resolved, "error_args": args, "code": "keep"})
			encoded, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			var decoded map[string]any
			if err = json.Unmarshal(encoded, &decoded); err != nil {
				t.Fatal(err)
			}
			Body(400, decoded)
			if decoded["error"] != text || decoded["error_key"] != resolved || decoded["code"] != "keep" {
				t.Fatalf("proxy changed the reason: %v", decoded)
			}
		})
	}
}

func TestBusinessDetailsAndSecurityBoundaries(t *testing.T) {
	for _, tc := range []struct {
		raw, key string
		args     map[string]string
	}{
		{"quota exhausted: tunnels (current=4, limit=3)", "quotaDetails", map[string]string{"current": "4", "limit": "3", "resource": "resources"}},
		{"TCP/UDP tunnel quota exhausted: tcp (current=4, limit=3)", "quotaDetails", map[string]string{"current": "4", "limit": "3", "resource": "TCP/UDP tunnels"}},
		{"赠金与余额不足：当前可用 $4.00（赠金 $1.00 + 余额 $3.00），本次需支付 $8.00，请先充值后再支付", "balanceDetails", map[string]string{"available": "$4.00", "credit": "$1.00", "balance": "$3.00", "required": "$8.00"}},
		{"custom domain \"shop.example.com\" is not registered; run `calabi domains create shop.example.com` first", "domainNotRegistered", map[string]string{"domain": "shop.example.com"}},
	} {
		_, key, args, ok := Business(tc.raw, "")
		if !ok || key != "business."+tc.key {
			t.Fatalf("reason lost: %s => %s", tc.raw, key)
		}
		for k, v := range tc.args {
			if args[k] != v {
				t.Fatalf("%s lost %s: %v", tc.key, k, args)
			}
		}
	}
	if _, _, _, ok := Business("rpc error: code = Internal desc = domain not found", "client_offline"); ok {
		t.Fatal("internal failure was reclassified as a business refusal")
	}
	for key, args := range map[string]map[string]string{
		"quantityLimit":       {"limit": "sql: private diagnostic"},
		"domainNotRegistered": {"domain": "{{minimum}}"},
		"balanceDetails":      {"available": "secret", "credit": "$1.00", "balance": "$3.00", "required": "$8.00"},
	} {
		if _, ok := Format(key, args); ok {
			t.Fatalf("unsafe arguments accepted: %s", key)
		}
	}
	msg, key := Message(400, "store: unknown internal detail")
	if key != "invalid" || strings.Contains(msg, "store:") {
		t.Fatalf("unknown free text leaked: %q", msg)
	}
	unsafe := Body(400, map[string]any{"error": "rpc error: code = Internal desc = sql: private", "error_key": "business.quantityLimit", "error_args": map[string]string{"limit": "3"}}).(map[string]any)
	if unsafe["error_key"] != "internal" || unsafe["error_args"] != nil {
		t.Fatalf("metadata overrode an internal failure: %v", unsafe)
	}
	clean := Body(400, map[string]any{"error": "unused", "error_key": "business.domainNotRegistered", "error_args": map[string]string{"domain": "app.example.com", "debug": "private"}}).(map[string]any)
	if _, exists := clean["error_args"].(map[string]string)["debug"]; exists {
		t.Fatal("an undeclared diagnostic argument was retained")
	}
}

func TestAuthenticationSentinelsRemainCompatible(t *testing.T) {
	for _, tc := range []struct {
		code             int
		raw, legacy, key string
	}{
		{401, "rpc error: code = Unauthenticated desc = totp required", "totp required", "business.totpRequired"},
		{401, "rpc error: code = Unauthenticated desc = invalid totp code", "invalid totp code", "business.totpInvalid"},
		{401, "rpc error: code = Unauthenticated desc = invalid credentials", "invalid credentials", "invalidCredentials"},
		{403, "rpc error: code = PermissionDenied desc = email not verified", "email not verified", "emailNotVerified"},
	} {
		got := Body(tc.code, map[string]any{"error": tc.raw}).(map[string]any)
		if got["error"] != tc.legacy || got["error_key"] != tc.key {
			t.Fatalf("legacy login flow broken: %v", got)
		}
		if text, ok := got["message"].(string); !ok || text == "" || strings.Contains(text, "rpc error") {
			t.Fatalf("friendly fallback missing: %v", got)
		}
		encoded, _ := json.Marshal(got)
		var decoded map[string]any
		_ = json.Unmarshal(JSON(tc.code, encoded), &decoded)
		if decoded["error"] != tc.legacy || decoded["error_key"] != tc.key {
			t.Fatalf("proxy lost sign-in phase: %v", decoded)
		}
	}
}
