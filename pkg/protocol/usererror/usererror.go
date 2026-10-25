// Package usererror turns internal failures into safe, actionable API messages.
// It has no dependency on control-plane contracts and can be used by local APIs.
package usererror

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"unicode"
)

// JSON handles responses proxied from older servers, including HTML gateway
// failures. Extra fields such as business codes and recovery hints survive.
func JSON(code int, data []byte) []byte {
	if code < 400 {
		return data
	}
	var body map[string]any
	if json.Unmarshal(data, &body) != nil || body == nil {
		message, key := Message(code, "")
		if code >= 500 {
			slog.Warn("upstream returned a non-JSON error", "status", code, "detail", string(data))
		}
		body = map[string]any{"error": message, "error_key": key}
	}
	if _, ok := body["error"].(string); !ok || body["error"] == "" {
		body["error"] = http.StatusText(code)
	}
	result, _ := json.Marshal(Body(code, body))
	return result
}

var messages = map[string]string{
	"invalid":             "Please check the information you entered and try again.",
	"unauthenticated":     "Your session has expired. Please sign in again.",
	"forbidden":           "You do not have permission to perform this action. Contact your organization administrator if you need access.",
	"notFound":            "The requested item could not be found. It may have been removed. Refresh the page and try again.",
	"conflict":            "This item already exists or has changed. Refresh the page and try again.",
	"quota":               "A usage or request limit has been reached. Check your available quota or wait a moment before trying again.",
	"precondition":        "This action is not available in the current state. Refresh the page and check the requirements.",
	"unsupported":         "This feature is not available on this server. Check that your client and server are up to date.",
	"timeout":             "The request took too long. Please try again in a moment.",
	"unavailable":         "The service is temporarily unavailable. Please try again in a moment.",
	"internal":            "We could not complete your request. Please try again. If the problem continues, contact support.",
	"cancelled":           "The request was cancelled. Please try again if needed.",
	"invalidCredentials":  "The email address or password is incorrect. Please check them and try again.",
	"emailNotVerified":    "Please verify your email address before signing in. Check your inbox for the verification email.",
	"emailExists":         "This email address is already registered. Sign in or reset your password.",
	"insufficientBalance": "Your balance is insufficient. Add funds or choose another payment method.",
}

func statusKey(code int) string {
	switch code {
	case 400, 422:
		return "invalid"
	case 401:
		return "unauthenticated"
	case 403:
		return "forbidden"
	case 404:
		return "notFound"
	case 409:
		return "conflict"
	case 412:
		return "precondition"
	case 429:
		return "quota"
	case 408, 504:
		return "timeout"
	case 501:
		return "unsupported"
	case 502, 503:
		return "unavailable"
	case 499:
		return "cancelled"
	default:
		return "internal"
	}
}

// Message preserves useful business refusals but never exposes transport or
// server diagnostics. key is optional and lets a UI translate the English text.
func Message(code int, raw string) (message, key string) {
	msg := strings.TrimSpace(raw)
	// Errors may be wrapped more than once by downstream services.
	for strings.Contains(msg, "rpc error: code = ") {
		i := strings.Index(msg, "rpc error: code = ")
		rest := msg[i+len("rpc error: code = "):]
		grpcCode, desc, ok := strings.Cut(rest, " desc = ")
		if !ok {
			return messages[statusKey(code)], statusKey(code)
		}
		switch grpcCode {
		case "Unavailable":
			return messages["unavailable"], "unavailable"
		case "DeadlineExceeded":
			return messages["timeout"], "timeout"
		case "Internal", "Unknown", "DataLoss":
			return messages["internal"], "internal"
		case "Unimplemented":
			return messages["unsupported"], "unsupported"
		case "Canceled":
			return messages["cancelled"], "cancelled"
		case "InvalidArgument":
			code = http.StatusBadRequest
		case "Unauthenticated":
			code = http.StatusUnauthorized
		case "PermissionDenied":
			code = http.StatusForbidden
		case "NotFound":
			code = http.StatusNotFound
		case "AlreadyExists", "Aborted":
			code = http.StatusConflict
		case "ResourceExhausted":
			code = http.StatusTooManyRequests
		case "FailedPrecondition":
			code = http.StatusPreconditionFailed
		}
		msg = desc
	}
	known := map[string]string{
		"invalid credentials": "invalidCredentials", "invalid email or password": "invalidCredentials",
		"email not verified": "emailNotVerified", "email already registered": "emailExists",
		"email already exists": "emailExists", "insufficient balance": "insufficientBalance",
		"赠金与余额不足，请先充值后再支付":     "insufficientBalance",
		"missing bearer token": "unauthenticated", "invalid bearer token": "unauthenticated",
		"not authenticated": "unauthenticated", "invalid token": "unauthenticated",
		"insufficient role": "forbidden", "rate limited": "quota",
	}
	if k := known[strings.ToLower(msg)]; k != "" {
		return messages[k], k
	}
	if code < 500 {
		if text, key, _, ok := Business(msg, ""); ok {
			return text, key
		}
	}
	// Already-normalized responses survive local API proxying unchanged.
	for k, text := range messages {
		if msg == text {
			return text, k
		}
	}
	lower := strings.ToLower(msg)
	// Legacy Chinese-only messages cannot be translated reliably without a
	// business code. Supply an English fallback plus a translatable category.
	technical := msg == "" || strings.ContainsAny(msg, "\r\n<>") || strings.ContainsFunc(msg, func(r rune) bool { return unicode.Is(unicode.Han, r) })
	for _, fragment := range []string{"dial tcp", "dial unix", "connection refused", "connection reset", "transport:", "sql:", "sqlstate", "pq:", "ent:", "x509:", "tls:", "unexpected eof", "upstream", "decode body:", "json:", "context deadline", "context canceled"} {
		technical = technical || strings.Contains(lower, fragment)
	}
	if code >= http.StatusInternalServerError || technical {
		key = statusKey(code)
		if strings.Contains(lower, "dial tcp") || strings.Contains(lower, "dial unix") || strings.Contains(lower, "connection refused") || strings.Contains(lower, "connection reset") || strings.Contains(lower, "transport:") || strings.Contains(lower, "x509:") || strings.Contains(lower, "tls:") {
			key = "unavailable"
		}
		if strings.Contains(lower, "deadline") || strings.Contains(lower, "timeout") {
			key = "timeout"
		}
		if strings.Contains(lower, "context canceled") {
			key = "cancelled"
		}
		return messages[key], key
	}
	// Unknown free text has no reliable translation contract. Known business
	// reasons above retain their specifics; the rest use a localizable fallback.
	key = statusKey(code)
	return messages[key], key
}

// Body normalizes only error envelopes. Existing business codes and additional
// fields are retained; successful responses (including diagnostic logs) bypass it.
func Body(code int, body any) any {
	if code < 400 {
		return body
	}
	var raw string
	var hasError bool
	switch v := body.(type) {
	case map[string]any:
		raw, hasError = v["error"].(string)
	case map[string]string:
		raw, hasError = v["error"]
	default:
		return body
	}
	if !hasError {
		return body
	}
	msg, key := Message(code, raw)
	var args map[string]string
	if code < 500 && key != "internal" && key != "unavailable" && key != "timeout" && key != "cancelled" && key != "unsupported" {
		businessCode, existingKey := "", ""
		switch v := body.(type) {
		case map[string]any:
			businessCode, _ = v["code"].(string)
			existingKey, _ = v["error_key"].(string)
			args = stringArgs(v["error_args"])
		case map[string]string:
			businessCode = v["code"]
			existingKey = v["error_key"]
		}
		if strings.HasPrefix(existingKey, "business.") {
			if text, valid := Format(existingKey, args); valid {
				msg, key = text, existingKey
			} else if text, businessKey, businessArgs, ok := Business(raw, businessCode); ok {
				msg, key, args = text, businessKey, businessArgs
			}
		} else if text, businessKey, businessArgs, ok := Business(raw, businessCode); ok {
			msg, key, args = text, businessKey, businessArgs
		}
	}
	if strings.HasPrefix(key, "business.") {
		clean := map[string]string{}
		if template, ok := businessCatalog.Messages[strings.TrimPrefix(key, "business.")]; ok {
			for _, slot := range templateSlot.FindAllStringSubmatch(template, -1) {
				if value, exists := args[slot[1]]; exists && validArgument(slot[1], value) {
					clean[slot[1]] = value
				}
			}
		}
		args = clean
	} else {
		args = nil
	}
	if msg != raw && code >= 500 {
		slog.Warn("API request failed", "status", code, "detail", raw)
	}
	// Older clients drive their sign-in steps from these small English sentinels.
	// Keep that wire compatibility; new clients display the localized reason and
	// API consumers can use message as the readable English fallback.
	legacy := ""
	if code == http.StatusUnauthorized {
		switch key {
		case "business.totpRequired":
			legacy = "totp required"
		case "business.totpInvalid":
			legacy = "invalid totp code"
		case "invalidCredentials":
			legacy = "invalid credentials"
		}
	}
	if code == http.StatusForbidden && key == "emailNotVerified" {
		legacy = "email not verified"
	}
	switch v := body.(type) {
	case map[string]any:
		delete(v, "error_args")
		v["error"] = msg
		if legacy != "" {
			v["error"] = legacy
			v["message"] = msg
		}
		if key != "" {
			v["error_key"] = key
		}
		if len(args) > 0 && strings.HasPrefix(key, "business.") {
			v["error_args"] = args
		}
	case map[string]string:
		v["error"] = msg
		if legacy != "" {
			v["error"] = legacy
			v["message"] = msg
		}
		if key != "" {
			v["error_key"] = key
		}
		// A string-only envelope cannot hold structured interpolation arguments.
		// Upgrade it to the same public shape used by other handlers.
		if len(args) > 0 && strings.HasPrefix(key, "business.") {
			out := map[string]any{}
			for k, val := range v {
				out[k] = val
			}
			out["error_args"] = args
			return out
		}
	}
	return body
}
