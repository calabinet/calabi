package bffclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLegacyServerErrorIsFriendly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"rpc error: code = Unavailable desc = dial tcp 10.0.0.1:7001","code":"keep","hint":"One tunnel is already disabled."}`))
	}))
	defer srv.Close()
	err := New(srv.URL, "").Do(context.Background(), http.MethodGet, "/v1/me", nil, nil)
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Status != 503 {
		t.Fatalf("lost status: %v", err)
	}
	if strings.Contains(err.Error(), "rpc") || strings.Contains(err.Error(), "10.0.0.1") || !strings.Contains(err.Error(), "try again") {
		t.Fatalf("bad display: %v", err)
	}
	if !strings.Contains(string(apiErr.Body), `"code":"keep"`) {
		t.Fatalf("lost business code: %s", apiErr.Body)
	}
	if !strings.Contains(err.Error(), "One tunnel is already disabled.") {
		t.Fatalf("lost partial completion hint: %v", err)
	}
}

func TestNetworkFailureRetainsCauseWithoutDisplayingTransport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := New("http://127.0.0.1:1", "").Do(ctx, http.MethodGet, "/v1/me", nil, nil)
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "cancelled") || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("bad cancellation: %v", err)
	}
}
