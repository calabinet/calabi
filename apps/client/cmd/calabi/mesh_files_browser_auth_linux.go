//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type browserPeerKey struct{}

// This endpoint is never forwarded by the daemon console. Kernel credentials,
// not HTTP parameters or headers, authorize capability issuance and revocation.
func startBrowserAuth(ctx context.Context, socket, publicURL string, auth *browserAuth) (func(), error) {
	if st, err := os.Lstat(socket); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("invalid browser authorization socket")
		}
		conn, e := net.DialTimeout("unix", socket, time.Second)
		if e == nil {
			conn.Close()
			return nil, errors.New("browser authorization server already running")
		}
		if err = os.Remove(socket); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	l, err := net.Listen("unix", socket)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(socket, 0600); err != nil {
		l.Close()
		return nil, err
	}
	srv := &http.Server{ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, MaxHeaderBytes: 4096}
	srv.ConnContext = func(ctx context.Context, conn net.Conn) context.Context {
		allowed := false
		if u, ok := conn.(*net.UnixConn); ok {
			if raw, err := u.SyscallConn(); err == nil {
				_ = raw.Control(func(fd uintptr) {
					cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
					allowed = err == nil && (cred.Uid == 0 || cred.Uid == uint32(os.Geteuid()))
				})
			}
		}
		return context.WithValue(ctx, browserPeerKey{}, allowed)
	}
	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if allowed, _ := r.Context().Value(browserPeerKey{}).(bool); !allowed {
			http.Error(w, "forbidden", 403)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", 405)
			return
		}
		switch r.URL.Path {
		case "/pair":
			pair, err := auth.issuePair()
			if err != nil {
				http.Error(w, "pairing capacity reached", 429)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"url": publicURL + "#/mesh/files?pair=" + pair})
		case "/revoke-all":
			auth.revokeAll()
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		default:
			http.NotFound(w, r)
		}
	})
	stop := context.AfterFunc(ctx, func() { _ = srv.Close() })
	go func() { _ = srv.Serve(l) }()
	return func() { stop(); _ = srv.Close() }, nil
}

func browserAuthRequest(socket, action string) (string, error) {
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 4 * time.Second}
	response, err := client.Post("http://file-browser-auth/"+action, "application/json", nil)
	if err != nil {
		return "", fmt.Errorf("browser authorization unavailable; check the file service: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return "", fmt.Errorf("browser authorization request refused (%d)", response.StatusCode)
	}
	var v struct {
		URL string `json:"url"`
		OK  bool   `json:"ok"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&v); err != nil {
		return "", err
	}
	return v.URL, nil
}

func standaloneBrowserURL() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return browserAuthRequest(filepath.Join(dir, "Calabi", "file-agent", "browser-auth.sock"), "pair")
}
