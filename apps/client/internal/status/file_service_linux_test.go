//go:build linux

package status

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestFileServiceProxyRetainsIndependentAuthorization(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "file.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	service := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Host != "console.example:7500" || r.URL.Path != "/file-web/action" {
			t.Errorf("bad routing: %s %s", r.Host, r.URL.Path)
		}
		cookie, err := r.Cookie("calabi_file_browser")
		if err != nil || cookie.Value != "independent-file-key" {
			http.Error(w, "file authorization required", 401)
			return
		}
		_, _ = io.WriteString(w, "authorized")
	})}
	go service.Serve(listener)
	defer service.Close()
	handler := fileServiceProxy(socket)
	request := func(origin, cookie string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://console.example:7500/file-service/file-web/action", strings.NewReader(`{"action":"snapshot"}`))
		r.Header.Set("Origin", origin)
		r.Header.Set("X-Local-Token", "machine-console-token-is-not-file-authorization")
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: "calabi_file_browser", Value: cookie})
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if got := request("http://evil.example", "independent-file-key"); got.Code != 403 || calls.Load() != 0 {
		t.Fatal("cross-origin write reached file process")
	}
	if got := request("http://console.example:7500", ""); got.Code != 401 {
		t.Fatal("machine console credential granted file access")
	}
	if got := request("http://console.example:7500", "independent-file-key"); got.Code != 200 || got.Body.String() != "authorized" {
		t.Fatalf("authorized request failed: %d %s", got.Code, got.Body.String())
	}
	service.Close()
	if got := request("http://console.example:7500", "independent-file-key"); got.Code != 503 {
		t.Fatal("stopped service was not reported unavailable")
	}
}
