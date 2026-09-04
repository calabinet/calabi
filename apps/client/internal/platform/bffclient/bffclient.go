// Package bffclient is a minimal HTTP client the calabi CLI uses to talk
// to bff-console. / retired the per-CLI-command gRPC dial
// against identity-svc / cert-svc / domain-svc in favour of this thin
// wrapper, so production only needs a single public endpoint
// (CALABI_BFF_CONSOLE).
//
// Scope is intentionally tiny: no retry, no refresh-on-401 (CLI is one-
// shot — let it fail loudly and have the user re-run `calabi login`),
// no connection pool beyond http.DefaultTransport's defaults. The
// daemon's long-running paths (statusapi proxy, edgepicker, clientreg)
// build their own clients with timeouts tuned for their loops.
package bffclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is a single bff-console endpoint + bearer token. Safe for
// concurrent use; the underlying http.Client is reused across calls.
type Client struct {
	BaseURL string
	Token   string // bearer; empty = unauthenticated request (login)
	HTTP    *http.Client
}

// New builds a Client. baseURL is trimmed of trailing slashes so callers
// can pass paths starting with "/".
func New(baseURL, token string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

// Do performs an HTTP request and unmarshals the JSON response into
// `out` (pass nil to ignore the body).
//
//   - method: "GET" / "POST" / "DELETE" / "PUT" / "PATCH"
//   - path:   starts with "/", e.g. "/v1/orgs"
//   - body:   any → JSON-encoded; nil → no body
//   - out:    *T → JSON-decoded; nil → response body discarded
//
// On non-2xx status, returns an *Error carrying status code and the
// raw response body (which bff-console always wraps as JSON
// `{"error":"..."}` but we don't insist — print raw on weird upstreams).
func (c *Client) Do(ctx context.Context, method, path string, body, out any) error {
	if c == nil {
		return fmt.Errorf("bffclient: nil receiver")
	}
	if c.BaseURL == "" {
		return fmt.Errorf("bffclient: empty BaseURL")
	}
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal body: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reqBody)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20)) // 4MB cap
	if resp.StatusCode/100 != 2 {
		// Try to extract a friendlier error message from the JSON body.
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		msg := e.Error
		if msg == "" {
			msg = strings.TrimSpace(string(raw))
		}
		return &Error{Status: resp.StatusCode, Message: msg, Body: raw}
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decode %s %s: %w (body: %q)", method, path, err, raw)
	}
	return nil
}

// Error is the typed error Do returns for non-2xx responses.
type Error struct {
	Status  int
	Message string
	Body    []byte
}

func (e *Error) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("HTTP %d: %s", e.Status, e.Message)
	}
	return fmt.Sprintf("HTTP %d", e.Status)
}

// IsStatus returns true if err is an *Error with the given status code.
// Caller uses it to distinguish auth errors (401) from server errors.
func IsStatus(err error, code int) bool {
	if err == nil {
		return false
	}
	e, ok := err.(*Error)
	return ok && e.Status == code
}
