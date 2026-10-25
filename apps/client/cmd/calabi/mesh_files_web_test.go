package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestFileBrowserSecurity(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	key := strings.Repeat("a", 64)
	calls := 0
	b := &fileBrowser{root: root, authority: "127.0.0.1:7501", key: key, action: func(fileAction) (any, error) { calls++; return true, nil }}
	req := func(path, body, origin, cookie string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://"+b.authority+path, strings.NewReader(body))
		r.Header.Set("Origin", origin)
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: "calabi_file_browser", Value: cookie})
		}
		w := httptest.NewRecorder()
		b.ServeHTTP(w, r)
		return w
	}
	origin := "http://" + b.authority
	for _, tc := range []struct {
		path, body, origin, cookie string
		code                       int
	}{
		{"/file-web/action", `{"action":"snapshot"}`, origin, "", 401},
		{"/file-web/session", `{"key":"` + key + `"}`, "http://evil.example", "", 403},
		{"/file-web/action", `{"action":"snapshot"}`, "http://evil.example", key, 403},
		{"/file-web/action", `{"action":"pick"}`, origin, key, 400},
		{"/file-web/action", `{"action":"identity_reset"}`, origin, key, 400},
		{"/file-web/action", `{"action":"web_stage","names":["../outside"]}`, origin, key, 400},
		{"/file-web/action", `{"action":"snapshot","unknown":true}`, origin, key, 400},
	} {
		if w := req(tc.path, tc.body, tc.origin, tc.cookie); w.Code != tc.code {
			t.Fatal(tc, w.Code, w.Body.String())
		}
	}
	if calls != 0 {
		t.Fatal("unauthorized operation reached agent")
	}
	login := req("/file-web/session", `{"key":"`+key+`"}`, origin, "")
	if login.Code != 200 {
		t.Fatal(login.Body.String())
	}
	cookies := login.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe cookie")
	}
	if w := req("/file-web/action", `{"action":"snapshot"}`, origin, key); w.Code != 200 || calls != 1 {
		t.Fatal(w.Code, calls)
	}
	r := httptest.NewRequest("GET", "http://evil.example/file-web/ping", nil)
	r.AddCookie(cookies[0])
	w := httptest.NewRecorder()
	b.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("host check missing")
	}
	for _, name := range []string{"..", "../outside", "/etc/passwd", "a/b", "a\\b"} {
		if browserName(name) {
			t.Fatal(name)
		}
	}
}
func TestFileBrowserAddressKey(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:7501", "192.168.1.2:7501", "100.64.0.17:7501", "localhost:7501", "100.64.0.16:0"} {
		if browserAddress(addr, "100.64.0.16") == nil {
			t.Fatal(addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:7501", "100.64.0.16:7501"} {
		if err := browserAddress(addr, "100.64.0.16"); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	a, err := browserKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := browserKey(dir)
	if err != nil || a != b || len(a) != 64 {
		t.Fatal("key not persisted")
	}
}
