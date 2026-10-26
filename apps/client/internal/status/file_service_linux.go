//go:build linux

package status

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// The root console forwards only to this instance's fixed Unix endpoint.
// File operations still require the ordinary user's independent browser key.
func fileServiceRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/file-service/", func(w http.ResponseWriter, r *http.Request) {
		addr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
		if !ok {
			http.Error(w, "file service unavailable", 503)
			return
		}
		_, port, err := net.SplitHostPort(addr.String())
		if err != nil {
			http.Error(w, "file service unavailable", 503)
			return
		}
		if _, err = strconv.ParseUint(port, 10, 16); err != nil {
			http.Error(w, "file service unavailable", 503)
			return
		}
		socket := filepath.Join("/run", "calabi-files-"+port, "web.sock")
		fileServiceProxy(socket).ServeHTTP(w, r)
	})
}

func fileServiceProxy(socket string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/file-service/available" {
			conn, err := net.DialTimeout("unix", socket, time.Second)
			if err == nil {
				conn.Close()
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(w).Encode(map[string]bool{"supported": err == nil})
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			origin, err := url.Parse(r.Header.Get("Origin"))
			if err != nil || origin.Host != r.Host || (origin.Scheme != "http" && origin.Scheme != "https") {
				http.Error(w, "invalid file service origin", 403)
				return
			}
		}
		proxy := &httputil.ReverseProxy{Director: func(req *http.Request) {
			req.URL.Scheme, req.URL.Host = "http", "file-service"
			req.URL.Path = strings.TrimPrefix(req.URL.Path, "/file-service")
			req.URL.RawPath = ""
			req.Header.Del("X-Forwarded-Host")
		}, Transport: &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", socket)
		}}, ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "file service unavailable; check calabi mesh files service status", 503)
		}}
		proxy.ServeHTTP(w, r)
	})
}
