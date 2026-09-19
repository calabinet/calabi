// Package mobile is the Go core of the phone clients, bound into the apps with
// gomobile.
//
// The phone is a device on its org's meshnet. Everything that talks to the
// network lives here — sign-in, the control plane, the WireGuard datapath —
// and the app is a thin native shell around it: it draws the screens, owns the
// VPN, and answers the few questions only the platform can (Platform).
//
// The exported surface is deliberately tiny, because every exported name has to
// cross the gomobile boundary: New, Core's methods, Response, Platform. The app
// talks to everything else through Core.Call, an in-process HTTP-shaped API with
// the same /v1/* paths and JSON the desktop client's local console uses.
package mobile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/calabi/calabi/apps/client/internal/creds"
	"github.com/calabi/calabi/apps/client/internal/hostnet"
	"github.com/calabi/calabi/apps/client/internal/selfhosted"
)

// Platform is what the app implements for the core.
type Platform interface {
	// ApplyNetwork (re)establishes the VPN with the given settings — a JSON
	// object {"addresses": [...], "routes": [...], "mtu": n} — and returns the
	// tun file descriptor to use from now on. On Android that is the descriptor
	// VpnService.Builder.establish() returned, detached, so the core owns it.
	ApplyNetwork(settingsJSON string) (int32, error)
	// Protect keeps the socket fd out of the VPN (Android: VpnService.protect).
	// Returns true when there is no VPN running to protect it from.
	Protect(fd int32) bool
	// Interfaces lists the device's network interfaces as JSON:
	// [{"name": "wlan0", "up": true, "loopback": false, "addrs": ["192.168.1.7/24"]}].
	// Android 11+ refuses the netlink query Go would otherwise use.
	Interfaces() (string, error)
	// Log receives the core's log lines. level is slog's: -4 debug, 0 info,
	// 4 warn, 8 error.
	Log(level int32, msg string)
}

// config is what the app passes to New, as JSON.
type config struct {
	// StateDir is where the core keeps its files: credentials, settings, the
	// device's mesh key. The app's private files directory.
	StateDir string `json:"state_dir"`
	// BFFURL is the control plane's public API (https://api.calabi.net).
	BFFURL string `json:"bff_url"`
	// DeviceName is the default mesh name (the phone's model) until the user
	// picks one.
	DeviceName string `json:"device_name"`
	// CoordPlaintext dials the coordinator without TLS: a development stack
	// only, never a release build.
	CoordPlaintext bool `json:"coord_plaintext"`
}

// Core is one phone client. Create it once per process with New.
type Core struct {
	cfg      config
	platform Platform
	logger   *slog.Logger
	logs     *logRing
	hc       *http.Client
	api      http.Handler

	mu     sync.Mutex
	engine *engine

	selfMu sync.Mutex // guards self.json (self.go)

	// A read-only session with a self-hosted server, for its lists while the
	// phone is not connected (selfhosted_view.go).
	viewer selfhosted.Viewer
}

// New creates the core. configJSON is a config object (see config).
func New(configJSON string, p Platform) (*Core, error) {
	if p == nil {
		return nil, errors.New("mobile: New needs a Platform")
	}
	var cfg config
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return nil, fmt.Errorf("mobile: config: %w", err)
	}
	if cfg.StateDir == "" || cfg.BFFURL == "" {
		return nil, errors.New("mobile: config needs state_dir and bff_url")
	}
	cfg.BFFURL = strings.TrimRight(cfg.BFFURL, "/")

	c := &Core{cfg: cfg, platform: p, logs: newLogRing(2000)}
	c.logger = slog.New(&platformLogHandler{platform: p, ring: c.logs, level: slog.LevelInfo})

	// Process-wide, like the VPN they describe. Installed before anything opens
	// a socket (see hostnet).
	creds.SetDataDir(cfg.StateDir)
	hostnet.SetSocketHook(func(fd uintptr) error {
		if !p.Protect(int32(fd)) {
			return errors.New("the VPN refused to protect the socket")
		}
		return nil
	})
	hostnet.SetInterfaceLister(func() ([]hostnet.Interface, error) {
		js, err := p.Interfaces()
		if err != nil {
			return nil, err
		}
		return parseInterfaces(js)
	})

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return hostnet.Dialer().DialContext(ctx, network, addr)
	}
	c.hc = &http.Client{Timeout: 20 * time.Second, Transport: transport}
	c.api = c.routes()
	return c, nil
}

// Response is Call's result: an HTTP status and a JSON body.
type Response struct {
	Status int32
	Body   []byte
}

// Call runs one request against the core's local API (see routes) in-process.
// body is JSON or nil.
func (c *Core) Call(method, path string, body []byte) *Response {
	req, err := http.NewRequestWithContext(context.Background(), method, path, bytes.NewReader(body))
	if err != nil {
		return jsonResponse(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	rec := &recorder{header: http.Header{}, status: http.StatusOK}
	c.api.ServeHTTP(rec, req)
	return &Response{Status: int32(rec.status), Body: rec.body.Bytes()}
}

// Connect joins the meshnet. The app calls it once its VPN service is running
// and allowed to establish; the VPN itself is established by the core, through
// Platform.ApplyNetwork, as soon as the coordinator assigns an address.
func (c *Core) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.engine != nil {
		return nil
	}
	if c.selfHosted() == nil {
		if cfg, err := creds.Load(); err != nil || cfg == nil || cfg.AccessToken == "" {
			return errors.New("mobile: not signed in")
		}
	}
	c.engine = startEngine(c)
	return nil
}

// Disconnect leaves the meshnet and waits until the datapath is torn down.
func (c *Core) Disconnect() {
	c.mu.Lock()
	e := c.engine
	c.engine = nil
	c.mu.Unlock()
	if e != nil {
		e.stop()
	}
}

// NetworkChanged tells the core the device's network changed (Wi-Fi to
// cellular, a new network). Call it from the platform's network callback.
func (c *Core) NetworkChanged() {
	// Pooled connections belong to the network that just went away.
	c.hc.CloseIdleConnections()
	c.mu.Lock()
	e := c.engine
	c.mu.Unlock()
	if e != nil {
		e.networkChanged()
	}
}

// reconnect restarts a running session so it picks up changed settings or a
// changed identity. A no-op when not connected.
func (c *Core) reconnect() {
	c.mu.Lock()
	e := c.engine
	if e == nil {
		c.mu.Unlock()
		return
	}
	c.engine = nil
	c.mu.Unlock()
	e.stop()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.engine == nil {
		c.engine = startEngine(c)
	}
}

func (c *Core) currentEngine() *engine {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.engine
}

// parseInterfaces decodes Platform.Interfaces.
func parseInterfaces(js string) ([]hostnet.Interface, error) {
	var in []struct {
		Name     string   `json:"name"`
		Up       bool     `json:"up"`
		Loopback bool     `json:"loopback"`
		Addrs    []string `json:"addrs"`
	}
	if err := json.Unmarshal([]byte(js), &in); err != nil {
		return nil, fmt.Errorf("mobile: interfaces: %w", err)
	}
	out := make([]hostnet.Interface, 0, len(in))
	for _, it := range in {
		ifc := hostnet.Interface{Name: it.Name, Up: it.Up, Loopback: it.Loopback}
		for _, a := range it.Addrs {
			if p, err := netip.ParsePrefix(a); err == nil {
				ifc.Addrs = append(ifc.Addrs, hostnet.Address{Addr: p.Addr(), Bits: p.Bits()})
			} else if ip, err := netip.ParseAddr(a); err == nil {
				ifc.Addrs = append(ifc.Addrs, hostnet.Address{Addr: ip, Bits: -1})
			}
		}
		out = append(out, ifc)
	}
	return out, nil
}

// recorder is the minimal http.ResponseWriter Call needs.
type recorder struct {
	header http.Header
	status int
	wrote  bool
	body   bytes.Buffer
}

func (r *recorder) Header() http.Header { return r.header }

func (r *recorder) WriteHeader(status int) {
	if !r.wrote {
		r.status, r.wrote = status, true
	}
}

func (r *recorder) Write(b []byte) (int, error) {
	r.wrote = true
	return r.body.Write(b)
}

func jsonResponse(status int, v any) *Response {
	b, _ := json.Marshal(v)
	return &Response{Status: int32(status), Body: b}
}

// platformLogHandler sends log records to the app and keeps the recent ones for
// the diagnostics export.
type platformLogHandler struct {
	platform Platform
	ring     *logRing
	level    slog.Level
	attrs    []slog.Attr
	group    string
}

func (h *platformLogHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level }

func (h *platformLogHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Message)
	write := func(a slog.Attr) bool {
		if a.Equal(slog.Attr{}) {
			return true
		}
		b.WriteByte(' ')
		if h.group != "" {
			b.WriteString(h.group)
			b.WriteByte('.')
		}
		b.WriteString(a.Key)
		b.WriteByte('=')
		b.WriteString(a.Value.Resolve().String())
		return true
	}
	for _, a := range h.attrs {
		write(a)
	}
	r.Attrs(write)
	line := b.String()
	h.ring.add(r.Time, r.Level, line)
	h.platform.Log(int32(r.Level), line)
	return nil
}

func (h *platformLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	cp := *h
	cp.attrs = append(append([]slog.Attr(nil), h.attrs...), attrs...)
	return &cp
}

func (h *platformLogHandler) WithGroup(name string) slog.Handler {
	cp := *h
	if cp.group != "" {
		name = cp.group + "." + name
	}
	cp.group = name
	return &cp
}

// logRing keeps the last lines logged, for GET /v1/logs.
type logRing struct {
	mu    sync.Mutex
	lines []string
	next  int
	full  bool
}

func newLogRing(n int) *logRing { return &logRing{lines: make([]string, n)} }

func (l *logRing) add(t time.Time, level slog.Level, line string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines[l.next] = t.UTC().Format(time.RFC3339) + " " + level.String() + " " + line
	l.next = (l.next + 1) % len(l.lines)
	if l.next == 0 {
		l.full = true
	}
}

func (l *logRing) write(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	start, n := 0, l.next
	if l.full {
		start, n = l.next, len(l.lines)
	}
	for i := 0; i < n; i++ {
		_, _ = io.WriteString(w, l.lines[(start+i)%len(l.lines)]+"\n")
	}
}

// meshNameFor turns a device model or a user's choice into a mesh name: the
// rules the desktop client applies (lowercase, [a-z0-9-], at most 63). A name
// with nothing left falls back to "phone".
func meshNameFor(raw string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(raw)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '.' || r == '_' || r == ' ':
			b.WriteByte('-')
		}
	}
	label := strings.Trim(b.String(), "-")
	for strings.Contains(label, "--") {
		label = strings.ReplaceAll(label, "--", "-")
	}
	if len(label) > 63 {
		label = strings.Trim(label[:63], "-")
	}
	if label == "" {
		return "phone"
	}
	return label
}
