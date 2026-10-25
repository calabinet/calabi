package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/status"
)

// This listener belongs to an ordinary user's file agent, never the daemon.
// A dedicated capability protects private records; daemon console credentials
// cannot access it. Remote binding is restricted to the current overlay IP.
type fileBrowser struct {
	d                         *desktopFileAgent
	root                      *os.Root
	directory, authority, key string
	action                    func(fileAction) (any, error)
}

func browserAddress(addr, overlay string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return errors.New("web address must be an explicit IP:port")
	}
	ip, err := netip.ParseAddr(host)
	p, perr := strconv.Atoi(port)
	if err != nil || perr != nil || p < 1 || p > 65535 || ip.IsUnspecified() || (!ip.IsLoopback() && (ip.String() != overlay || !netip.MustParsePrefix("100.64.0.0/10").Contains(ip))) {
		return errors.New("web listener must use loopback or this device's current overlay IP")
	}
	return nil
}

func (d *desktopFileAgent) serveBrowser(addr, directory string) error {
	view, err := d.metadata()
	if err != nil {
		return err
	}
	if err := browserAddress(addr, view.Overlay); err != nil {
		return err
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		return err
	}
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		return err
	}
	private, err := filepath.EvalSymlinks(d.dir)
	if err != nil {
		return err
	}
	// Do not grant the browser a directory containing the agent's private keys.
	for _, pair := range [][2]string{{directory, private}, {private, directory}} {
		rel, e := filepath.Rel(pair[0], pair[1])
		if e == nil && (rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))) {
			return errors.New("web directory must be separate from the private file-agent directory")
		}
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	key, err := browserKey(d.dir)
	if err != nil {
		return err
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	web := &fileBrowser{d: d, root: root, directory: directory, authority: l.Addr().String(), key: key, action: d.handle}
	srv := &http.Server{Handler: web, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	stop := context.AfterFunc(d.ctx, func() { _ = srv.Close() })
	defer stop()
	fmt.Printf("File browser (private access link; do not share): http://%s/#/mesh/files?key=%s\n", web.authority, key)
	fmt.Printf("Server file directory: %s\nReception starts off; keep this process running.\n", directory)
	err = srv.Serve(l)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func browserKey(directory string) (string, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return "", err
	}
	defer root.Close()
	b, err := root.ReadFile("browser-access-key")
	if errors.Is(err, os.ErrNotExist) {
		var secret [32]byte
		if _, err = rand.Read(secret[:]); err != nil {
			return "", err
		}
		b = []byte(hex.EncodeToString(secret[:]))
		f, e := root.OpenFile("browser-access-key", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return "", e
		}
		_, err = f.Write(b)
		if err == nil {
			err = f.Sync()
		}
		err = errors.Join(err, f.Close())
	}
	if err != nil {
		return "", err
	}
	if _, err := hex.DecodeString(string(b)); err != nil || len(b) != 64 {
		return "", errors.New("invalid private browser access key")
	}
	return string(b), nil
}

func browserJSON(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}
func browserError(w http.ResponseWriter, code int, message string) {
	browserJSON(w, code, map[string]string{"error": message})
}

func (b *fileBrowser) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
	if r.Host != b.authority {
		browserError(w, 403, "invalid browser host")
		return
	}
	if strings.HasPrefix(r.URL.Path, "/file-web/") {
		if r.Method == "POST" && r.Header.Get("Origin") != "http://"+b.authority {
			browserError(w, 403, "invalid browser origin")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if r.URL.Path == "/file-web/session" && r.Method == "POST" {
			var v struct {
				Key string `json:"key"`
			}
			if json.NewDecoder(r.Body).Decode(&v) != nil || len(v.Key) != 64 || subtle.ConstantTimeCompare([]byte(v.Key), []byte(b.key)) != 1 {
				browserError(w, 401, "invalid browser access key")
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "calabi_file_browser", Value: b.key, HttpOnly: true, SameSite: http.SameSiteStrictMode, Path: "/file-web/"})
			browserJSON(w, 200, map[string]bool{"ok": true})
			return
		}
		cookie, err := r.Cookie("calabi_file_browser")
		if err != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(b.key)) != 1 {
			browserError(w, 401, "browser authentication required")
			return
		}
		b.api(w, r)
		return
	}
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}
	if r.URL.Path == "/file-web-config.js" {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = io.WriteString(w, "window.__CALABI_FILE_WEB__=true;")
		return
	}
	ui, err := status.UIFileSystem()
	if err != nil {
		http.Error(w, "UI unavailable", 500)
		return
	}
	if r.URL.Path == "/" {
		body, err := fs.ReadFile(ui, "index.html")
		if err != nil {
			http.Error(w, "UI unavailable", 500)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, strings.Replace(string(body), "<head>", "<head><script src=\"/file-web-config.js\"></script>", 1))
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/assets/") {
		http.NotFound(w, r)
		return
	}
	http.FileServer(http.FS(ui)).ServeHTTP(w, r)
}

func browserName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\\\x00") && !filepath.IsAbs(name)
}

func (b *fileBrowser) api(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == "GET" && r.URL.Path == "/file-web/ping":
		browserJSON(w, 200, map[string]bool{"ok": true})
		return
	case r.Method == "GET" && r.URL.Path == "/file-web/catalog":
		f, err := b.root.Open(".")
		if err != nil {
			browserError(w, 500, "server directory unavailable")
			return
		}
		defer f.Close()
		entries, err := f.ReadDir(1025)
		if err != nil && !errors.Is(err, io.EOF) {
			browserError(w, 500, "server directory unavailable")
			return
		}
		if len(entries) > 1024 {
			browserError(w, 400, "server directory contains too many entries (maximum 1024)")
			return
		}
		files := []map[string]any{}
		for _, entry := range entries {
			if entry.Type().IsRegular() {
				info, e := entry.Info()
				if e == nil {
					files = append(files, map[string]any{"name": entry.Name(), "size": info.Size()})
				}
			}
		}
		sort.Slice(files, func(i, j int) bool { return files[i]["name"].(string) < files[j]["name"].(string) })
		browserJSON(w, 200, map[string]any{"directory": b.directory, "files": files})
		return
	case r.Method == "GET" && r.URL.Path == "/file-web/mesh":
		v, err := b.d.metadata()
		if err != nil {
			browserError(w, 503, err.Error())
			return
		}
		peers := []map[string]any{}
		for _, member := range v.Members {
			name := ""
			for _, p := range v.Peers {
				if p.Grant.DeviceKey == member.DeviceKey {
					name = p.Name
					break
				}
			}
			peers = append(peers, map[string]any{"public_key": member.DeviceKey, "allowed_ips": []string{member.IP + "/32"}, "name": name})
		}
		browserJSON(w, 200, map[string]any{"up": v.Ready, "overlay": v.Overlay, "peers": peers})
		return
	case r.Method == "POST" && r.URL.Path == "/file-web/logout":
		http.SetCookie(w, &http.Cookie{Name: "calabi_file_browser", Value: "", Path: "/file-web/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
		browserJSON(w, 200, map[string]bool{"ok": true})
		return
	case r.Method == "POST" && r.URL.Path == "/file-web/action":
		var a struct {
			fileAction
			Names  []string `json:"names"`
			Name   string   `json:"name"`
			Locale string   `json:"locale"`
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if dec.Decode(&a) != nil {
			browserError(w, 400, "invalid file action")
			return
		}
		var result any
		var err error
		switch a.Action {
		case "supported":
			result = map[string]bool{"supported": true}
		case "web_stage":
			if len(a.Names) < 1 || len(a.Names) > 32 {
				err = errors.New("select 1..32 server files")
				break
			}
			for _, name := range a.Names {
				if !browserName(name) {
					browserError(w, 400, "invalid server file name")
					return
				}
			}
			b.d.opMu.Lock()
			var workspaceErr error
			ws, workspaceErr := b.d.ensure()
			if workspaceErr != nil {
				err = workspaceErr
			} else {
				for _, name := range a.Names {
					if !browserName(name) {
						err = errors.New("invalid server file name")
						break
					}
					var f *os.File
					f, err = b.root.Open(name)
					if err != nil {
						break
					}
					info, e := f.Stat()
					_ = f.Close()
					if e != nil || !info.Mode().IsRegular() {
						err = errors.New("server file unavailable")
						break
					}
					_, err = ws.ReferenceLocalChecked(ws.Context(), filepath.Join(b.directory, name), info)
					if err != nil {
						break
					}
				}
			}
			b.d.opMu.Unlock()
			if err == nil {
				result, err = b.action(fileAction{Action: "snapshot"})
			}
		case "web_save":
			if !browserName(a.Name) {
				err = errors.New("invalid server file name")
				break
			}
			b.d.opMu.Lock()
			ws, e := b.d.ensure()
			err = e
			if err == nil {
				var f *os.File
				f, err = b.root.OpenFile(a.Name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if err == nil {
					err = ws.Agent.CopyCompleted(ws.Context(), a.ID, f)
					if err == nil {
						err = f.Sync()
					}
					err = errors.Join(err, f.Close())
					if err != nil {
						_ = b.root.Remove(a.Name)
					}
				}
			}
			b.d.opMu.Unlock()
			if err == nil {
				result, err = b.action(fileAction{Action: "snapshot"})
			}
		case "snapshot", "receiving", "send", "decide", "pause", "resume", "cancel", "pause_receive", "resume_receive", "cancel_receive", "forget_job", "forget_receive", "forget_source", "cancel_preparing", "identity_status":
			result, err = b.action(a.fileAction)
		default:
			err = errors.New("unsupported browser file action")
		}
		if err != nil {
			browserError(w, 400, err.Error())
			return
		}
		browserJSON(w, 200, result)
		return
	}
	http.NotFound(w, r)
}
