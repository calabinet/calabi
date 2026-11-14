package filetransfer

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/gofrs/flock"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Grant struct {
	ClipboardTransport bool   `json:"clipboard_transport,omitempty"`
	Path               string `json:"path,omitempty"`
	Peer               Peer   `json:"peer"`
	DeviceKey          string `json:"device_key"`
	Port               uint16 `json:"port"`
	Receiving          bool   `json:"receiving"`
	Assistance         bool   `json:"assistance,omitempty"`
}
type AgentConfig struct {
	ClipboardPeer   func(Grant) bool // local desktop capability and current owned-device check
	AssistDenialLog func(netip.Addr, string)
	HandshakeLookup func(netip.Addr) (Grant, error)
	HandshakeLog    func(netip.Addr, string, bool)
	// Optional ordinary-user service, dispatched only after the peer and ACL checks.
	Assist    func(context.Context, Grant, http.ResponseWriter, *http.Request)
	Authority func() bool // optional OS-user lease check; no HTTP token can substitute for it
	Identity  *Identity
	Directory string // existing private directory of this ordinary user, per scope
	Scope     string
	LocalIP   netip.Addr
	Port      uint16
	Kbps      int
	MaxBytes  int64
	Resolve   func(netip.Addr) (Grant, bool)
	Incoming  func(netip.Addr, uint16) bool
}
type agentReceiver struct {
	grant    Grant
	receiver *Receiver
	handler  http.Handler
}
type Received struct {
	DeviceKey string   `json:"device_key"`
	IP        string   `json:"ip"`
	Transfer  Transfer `json:"transfer"`
}

// Agent belongs to the interactive user process, never the privileged mesh
// service. It owns the only file listener, shared budget and private inbox.
type Agent struct {
	copyMu             sync.Mutex
	copySession        *meshCopySession
	lock               *flock.Flock
	identityUse        *flock.Flock
	cfg                AgentConfig
	root               *os.Root
	mu                 sync.Mutex
	admission          sync.Mutex
	receivers          map[string]*agentReceiver
	budget             *Pacer
	relayBudget        *Pacer
	gate               chan struct{}
	assistMu           sync.Mutex
	assistCtx          context.Context
	stopAssist         context.CancelFunc
	clipboardReceiving atomic.Bool
	receiving          atomic.Bool
	closed             atomic.Bool
	retiring           atomic.Bool
	maintenance        sync.RWMutex
	server             *http.Server
	ctx                context.Context
	cancel             context.CancelFunc
}

func NewAgent(cfg AgentConfig) (*Agent, error) {
	if cfg.Identity == nil || cfg.Scope == "" || cfg.Resolve == nil || cfg.Incoming == nil || !cfg.LocalIP.IsValid() || cfg.LocalIP.IsUnspecified() || cfg.Port < 1024 || cfg.MaxBytes <= 0 {
		return nil, errors.New("incomplete file agent configuration")
	}
	var identityUse *flock.Flock
	ready := false
	if cfg.Identity.directory != "" {
		var err error
		identityUse, err = identityLock(cfg.Identity.directory, "file-identity-use.lock")
		if err != nil {
			return nil, err
		}
		defer func() {
			if !ready {
				identityUse.Unlock()
			}
		}()
		current, err := LoadIdentity(cfg.Identity.directory)
		if err != nil {
			return nil, err
		}
		if current.Fingerprint != cfg.Identity.Fingerprint {
			return nil, errors.New("file identity changed; reopen file transfers")
		}
	}
	budget, err := NewPacer(cfg.Kbps)
	if err != nil {
		return nil, err
	}
	relayBudget, _ := NewPacer(cfg.Kbps)
	relayBudget.SetDeviceLimit(DefaultKbps)
	lock := flock.New(filepath.Join(cfg.Directory, "workspace.lock"))
	locked, err := lock.TryLock()
	if err != nil {
		return nil, err
	}
	if !locked {
		return nil, errors.New("another file agent owns this private workspace")
	}
	root, err := os.OpenRoot(cfg.Directory)
	if err != nil {
		_ = lock.Unlock()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	a := &Agent{lock: lock, identityUse: identityUse, cfg: cfg, root: root, receivers: map[string]*agentReceiver{}, budget: budget, relayBudget: relayBudget, gate: make(chan struct{}, 1), ctx: ctx, cancel: cancel}
	// Load prior private inboxes without requiring peers to be online. Serving
	// them still requires fresh coordinator identity and local authorization.
	d, err := root.Open(".")
	if err != nil {
		a.Close()
		return nil, err
	}
	entries, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		a.Close()
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "peer-") || !validID(strings.TrimPrefix(e.Name(), "peer-")) {
			continue
		}
		pr, err := root.OpenRoot(e.Name())
		if err != nil {
			a.Close()
			return nil, err
		}
		f, err := pr.Open("peer.json")
		if err != nil {
			pr.Close()
			a.Close()
			return nil, err
		}
		var g Grant
		err = json.NewDecoder(io.LimitReader(f, 8193)).Decode(&g)
		f.Close()
		pr.Close()
		if err != nil || g.Peer.Validate() != nil || g.DeviceKey == "" || a.peerDir(g) != e.Name() {
			a.Close()
			return nil, errors.New("invalid private peer inbox")
		}
		if _, err := a.receiver(g, false); err != nil {
			a.Close()
			return nil, err
		}
	}
	if err := a.checkQuota(0, false); err != nil {
		a.Close()
		return nil, err
	}
	ready = true
	return a, nil
}

func (a *Agent) peerDir(g Grant) string {
	h := sha256.Sum256([]byte(a.cfg.Scope + func() string {
		if g.ClipboardTransport {
			return "/rdp-clipboard"
		}
		return ""
	}() + "\x00" + g.DeviceKey + "\x00" + g.Peer.IP.String() + "\x00" + g.Peer.Fingerprint))
	return "peer-" + hex.EncodeToString(h[:])
}
func (a *Agent) receiver(g Grant, create bool) (*agentReceiver, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	name := a.peerDir(g)
	if r := a.receivers[name]; r != nil {
		return r, nil
	}
	if len(a.receivers) >= 32 {
		return nil, errors.New("peer inbox limit reached")
	}
	if create {
		if err := a.root.Mkdir(name, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		pr, err := a.root.OpenRoot(name)
		if err != nil {
			return nil, err
		}
		err = writeRecord(pr, "peer.json", g)
		pr.Close()
		if err != nil {
			return nil, err
		}
	}
	// os.Root.Name is trusted local state, never a remotely provided path.
	pr, err := a.root.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	directory := pr.Name()
	pr.Close()
	allowed := func() bool {
		if a.closed.Load() || !(a.receiving.Load() && !g.ClipboardTransport || g.ClipboardTransport && a.ClipboardReceiving() && a.cfg.ClipboardPeer != nil && a.cfg.ClipboardPeer(g)) || (a.cfg.Authority != nil && !a.cfg.Authority()) || !a.cfg.Incoming(g.Peer.IP, a.cfg.Port) {
			return false
		}
		now, ok := a.cfg.Resolve(g.Peer.IP)
		return ok && now.Peer == g.Peer && now.DeviceKey == g.DeviceKey
	}
	r, err := NewReceiver(ReceiverConfig{Peer: g.Peer, Directory: directory, Kbps: a.cfg.Kbps, MaxBytes: a.cfg.MaxBytes, Budget: a.budget, RouteBudget: func() *Pacer { return a.pathBudget(g.Peer.IP) }, UploadGate: a.gate, Allowed: allowed, Durable: true, Scope: a.cfg.Scope + "/" + g.DeviceKey})
	if err != nil {
		return nil, err
	}
	ar := &agentReceiver{grant: g, receiver: r, handler: r.Handler()}
	a.receivers[name] = ar
	return ar, nil
}

func (a *Agent) checkQuota(extra int64, adding bool) error {
	var bytes int64
	count := 0
	for _, row := range a.List() {
		t := row.Transfer
		if t.State == "cancelled" || t.State == "failed" {
			continue
		}
		if t.Size > a.cfg.MaxBytes-bytes {
			return errors.New("inbox byte limit reached")
		}
		bytes += t.Size
		count++
	}
	if extra > a.cfg.MaxBytes-bytes || (adding && count >= MaxBatchFiles) {
		return errors.New("inbox byte or file limit reached")
	}
	return nil
}

func (a *Agent) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		a.maintenance.RLock()
		defer a.maintenance.RUnlock()
		addr, err := netip.ParseAddrPort(req.RemoteAddr)
		if err != nil {
			fail(w, 403, "invalid source")
			return
		}
		ip := addr.Addr().Unmap()
		assist := req.URL.Path == "/assist/v1/session"
		deny := func(reason string) {
			if assist && a.cfg.AssistDenialLog != nil {
				a.cfg.AssistDenialLog(ip, reason)
			}
			fail(w, 403, reason)
		}
		if a.closed.Load() || a.retiring.Load() || (a.cfg.Authority != nil && !a.cfg.Authority()) {
			deny("local session unavailable")
			return
		}
		g, ok := a.cfg.Resolve(ip)
		if !ok || g.Peer.IP != ip {
			deny("source grant unavailable")
			return
		}
		if req.TLS == nil || checkCertificate(*req.TLS, g.Peer.Fingerprint) != nil {
			deny("source certificate rejected")
			return
		}
		if !a.cfg.Incoming(ip, a.cfg.Port) {
			deny("incoming access denied")
			return
		}
		if req.URL.Path == "/rdp-copy/v2" {
			if a.cfg.ClipboardPeer == nil || !a.cfg.ClipboardPeer(g) {
				fail(w, 403, "remote copy unavailable")
				return
			}
			a.serveMeshCopy(g, w, req)
			return
		}
		if assist {
			a.assistMu.Lock()
			ctx := a.assistCtx
			a.assistMu.Unlock()
			if ctx == nil || ctx.Err() != nil {
				deny("assistance is disabled")
				return
			}
			a.cfg.Assist(ctx, g, w, req)
			return
		}
		clipboardRoute := strings.HasPrefix(req.URL.Path, "/rdp-files/v1/")
		if clipboardRoute {
			if !a.ClipboardReceiving() || a.cfg.ClipboardPeer == nil || !a.cfg.ClipboardPeer(g) {
				fail(w, 403, "RDP clipboard unavailable")
				return
			}
			g.ClipboardTransport = true
			clone := req.Clone(req.Context())
			u := *req.URL
			u.Path = strings.Replace(u.Path, "/rdp-files/v1/", "/file/v1/", 1)
			clone.URL = &u
			req = clone
		}
		if !clipboardRoute && !a.receiving.Load() {
			fail(w, 403, "file receiving is disabled")
			return
		}
		if req.Method == "POST" && req.URL.Path == "/file/v1/offers" {
			a.admission.Lock()
			defer a.admission.Unlock()
			b, err := io.ReadAll(http.MaxBytesReader(w, req.Body, 4096))
			if err != nil {
				fail(w, 400, "invalid offer")
				return
			}
			req.Body = io.NopCloser(bytes.NewReader(b))
			var o Offer
			if json.Unmarshal(b, &o) != nil || o.Size < 0 || o.Clipboard != clipboardRoute {
				fail(w, 400, "invalid offer")
				return
			}
			adding := true
			a.mu.Lock()
			existing := a.receivers[a.peerDir(g)]
			a.mu.Unlock()
			if existing != nil {
				for _, t := range existing.receiver.List() {
					if t.ClientID == o.ClientID {
						adding = false
						break
					}
				}
			}
			if adding {
				if err := a.checkQuota(o.Size, true); err != nil {
					fail(w, 409, err.Error())
					return
				}
			}
		}
		r, err := a.receiver(g, true)
		if err != nil {
			fail(w, 503, "private inbox unavailable")
			return
		}
		r.handler.ServeHTTP(w, req)
	})
}

func (a *Agent) Serve(listener net.Listener) (<-chan error, error) {
	addr, err := netip.ParseAddrPort(listener.Addr().String())
	if err != nil || addr.Addr().Unmap() != a.cfg.LocalIP.Unmap() || addr.Port() != a.cfg.Port {
		return nil, errors.New("listener must bind the exact mesh address and configured port")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.server != nil || a.closed.Load() {
		return nil, errors.New("agent listener already started or closed")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		addr, err := netip.ParseAddrPort(hello.Conn.RemoteAddr().String())
		if err != nil {
			return nil, err
		}
		ip := addr.Addr().Unmap()
		var g Grant
		if a.cfg.HandshakeLookup != nil {
			g, err = a.cfg.HandshakeLookup(ip)
			if err != nil {
				return nil, err
			}
		} else {
			var ok bool
			g, ok = a.cfg.Resolve(ip)
			if !ok {
				return nil, errors.New("unknown mesh peer")
			}
		}
		config := a.cfg.Identity.ServerTLS(g.Peer)
		if a.cfg.HandshakeLog != nil {
			verify := config.VerifyConnection
			config.VerifyConnection = func(cs tls.ConnectionState) error {
				err := verify(cs)
				if err == nil {
					a.cfg.HandshakeLog(ip, "peer_certificate_verified", true)
				}
				return err
			}
		}
		return config, nil
	}}
	a.server = &http.Server{Handler: a.Handler(), TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 90 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192, BaseContext: func(net.Listener) context.Context { return a.ctx }}
	if a.cfg.HandshakeLog != nil {
		a.server.ErrorLog = log.New(handshakeLogWriter{a.cfg.HandshakeLog}, "", 0)
	}
	done := make(chan error, 1)
	server := a.server
	go func() {
		err := server.ServeTLS(listener, "", "")
		a.mu.Lock()
		if a.server == server {
			a.server = nil
		}
		a.mu.Unlock()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			_ = a.SetAssistance(false)
			_ = a.SetReceiving(false)
		}
		done <- err
	}()
	return done, nil
}

// StopServing releases the fixed device port when this user is idle/off, so a
// second OS user can claim their own receiving session. It retains the private
// workspace and does not interrupt an outgoing transfer by this same user.
func (a *Agent) StopServing() error {
	_ = a.SetAssistance(false)
	err := errors.Join(a.SetReceiving(false), a.SetClipboardReceiving(false))
	a.mu.Lock()
	server := a.server
	a.server = nil
	a.mu.Unlock()
	if server != nil {
		err = errors.Join(err, server.Close())
	}
	return err
}

// Turning reception off revokes existing grants, rather than just hiding a UI.
func (a *Agent) SetReceiving(enabled bool) error {
	if !enabled {
		a.receiving.Store(false)
		a.mu.Lock()
		for _, r := range a.receivers {
			if r.grant.ClipboardTransport {
				continue
			}
			r.receiver.Interrupt()
		}
		a.mu.Unlock()
	}
	a.admission.Lock()
	defer a.admission.Unlock()
	if a.closed.Load() {
		return errors.New("file agent is closed")
	}
	a.receiving.Store(enabled)
	if enabled {
		return nil
	}
	var errs []error
	a.mu.Lock()
	receivers := make([]*Receiver, 0, len(a.receivers))
	for _, r := range a.receivers {
		if r.grant.ClipboardTransport {
			continue
		}
		receivers = append(receivers, r.receiver)
	}
	a.mu.Unlock()
	for _, r := range receivers {
		if err := r.CancelIncomplete(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
func (a *Agent) SetAssistance(enabled bool) error {
	a.assistMu.Lock()
	defer a.assistMu.Unlock()
	if !enabled {
		if a.stopAssist != nil {
			a.stopAssist()
		}
		a.assistCtx = nil
		a.stopAssist = nil
		return nil
	}
	if a.cfg.Assist == nil || a.closed.Load() {
		return errors.New("assistance unavailable")
	}
	if a.assistCtx == nil {
		a.assistCtx, a.stopAssist = context.WithCancel(a.ctx)
	}
	return nil
}
func (a *Agent) Assisting() bool {
	a.assistMu.Lock()
	defer a.assistMu.Unlock()
	return a.assistCtx != nil && a.assistCtx.Err() == nil
}
func (a *Agent) Receiving() bool { return a.receiving.Load() && !a.closed.Load() }
func (a *Agent) Alive() bool     { return !a.closed.Load() }

// Call only with a current authoritative map. Transport/lease loss pauses;
// membership, ACL or certificate changes revoke pending resume credentials.
func (a *Agent) Revalidate(memberAllowed func(string, netip.Addr) bool) error {
	a.mu.Lock()
	receivers := make([]*agentReceiver, 0, len(a.receivers))
	for _, r := range a.receivers {
		receivers = append(receivers, r)
	}
	a.mu.Unlock()
	var errs []error
	for _, r := range receivers {
		now, live := a.cfg.Resolve(r.grant.Peer.IP)
		revoke := !memberAllowed(r.grant.DeviceKey, r.grant.Peer.IP) || (live && (now.Peer != r.grant.Peer || now.DeviceKey != r.grant.DeviceKey))
		if revoke {
			if err := r.receiver.CancelIncomplete(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// This is a device file allowance, not an estimate of organization headroom.
// The existing server organization bucket remains authoritative. Unknown paths
// use the relay budget, including during direct-to-relay transitions.
func (a *Agent) pathBudget(ip netip.Addr) *Pacer {
	if g, ok := a.cfg.Resolve(ip); ok && g.Path == "direct" {
		return nil
	}
	return a.relayBudget
}

// Keep some device allowance for other traffic. This is not a QoS guarantee.
// Missing metadata retains the last known limit, initially the safe fallback.
func (a *Agent) ApplyKnownRelayLimit(kbps uint32) {
	if kbps > 0 {
		a.relayBudget.fixedLimit(int(max(uint64(1), min(uint64(a.cfg.Kbps), uint64(kbps)*3/4))))
	}
}
func (a *Agent) List() []Received {
	a.mu.Lock()
	receivers := make([]*agentReceiver, 0, len(a.receivers))
	for _, r := range a.receivers {
		receivers = append(receivers, r)
	}
	a.mu.Unlock()
	out := []Received{}
	for _, r := range receivers {
		for _, t := range r.receiver.List() {
			out = append(out, Received{DeviceKey: r.grant.DeviceKey, IP: r.grant.Peer.IP.String(), Transfer: t})
		}
	}
	slices.SortFunc(out, func(a, b Received) int {
		return cmp.Or(cmp.Compare(b.Transfer.CreatedUnixMs, a.Transfer.CreatedUnixMs), cmp.Compare(a.DeviceKey, b.DeviceKey), compareTransferOrder(a.Transfer, b.Transfer))
	})
	return out
}
func (a *Agent) find(id string) (*Receiver, error) {
	a.mu.Lock()
	receivers := make([]*agentReceiver, 0, len(a.receivers))
	for _, r := range a.receivers {
		receivers = append(receivers, r)
	}
	a.mu.Unlock()
	for _, r := range receivers {
		if r.receiver.find(id) != nil {
			return r.receiver, nil
		}
	}
	return nil, errors.New("unknown transfer")
}
func (a *Agent) Decide(ids []string, accept bool) error {
	if len(ids) < 1 || len(ids) > MaxBatchFiles {
		return errors.New("select 1..32 offered files")
	}
	a.admission.Lock()
	defer a.admission.Unlock()
	for _, id := range ids {
		r, err := a.find(id)
		if err != nil {
			return err
		}
		if err := r.Decide(id, accept); err != nil {
			return err
		}
	}
	return nil
}
func (a *Agent) Cancel(id string) error {
	r, err := a.find(id)
	if err != nil {
		return err
	}
	return r.Cancel(id)
}
func (a *Agent) Forget(id string) error {
	r, err := a.find(id)
	if err != nil {
		return err
	}
	return r.Forget(id)
}
func (a *Agent) CopyCompleted(ctx context.Context, id string, dst io.Writer) error {
	r, err := a.find(id)
	if err != nil {
		return err
	}
	return r.CopyCompleted(ctx, id, dst)
}
func (a *Agent) Sender(ip netip.Addr) (*BatchSender, error) { return a.sender(ip, false) }
func (a *Agent) sender(ip netip.Addr, clipboard bool) (*BatchSender, error) {
	g, ok := a.cfg.Resolve(ip)
	if !ok || (!clipboard && !g.Receiving) || (clipboard && (a.cfg.ClipboardPeer == nil || !a.cfg.ClipboardPeer(g))) {
		return nil, errors.New("peer is offline, unsupported or not receiving")
	}
	allowed := func() bool {
		now, ok := a.cfg.Resolve(ip)
		return !a.closed.Load() && (a.cfg.Authority == nil || a.cfg.Authority()) && ok && (now.Receiving && !clipboard || clipboard && a.cfg.ClipboardPeer != nil && a.cfg.ClipboardPeer(now)) && now.Peer == g.Peer && now.DeviceKey == g.DeviceKey && now.Port == g.Port
	}
	s, err := NewBatchSender(a.cfg.Identity, a.cfg.LocalIP, g.Peer, int(g.Port), a.budget, allowed, a.cfg.Scope)
	if err == nil {
		if clipboard {
			s.base = "https://" + netJoin(g.Peer.IP, int(g.Port)) + "/rdp-files/v1"
		}
		s.flow, _ = NewPacer(a.cfg.Kbps)
		s.flow.startAt(InitialKbps)
		s.pathBudget = func() *Pacer { return a.pathBudget(ip) }
		s.probePath = func() string {
			now, ok := a.cfg.Resolve(ip)
			if !ok {
				return ""
			}
			return now.Path
		}
	}
	return s, err
}
func (a *Agent) Close() error {
	if a.closed.Swap(true) {
		return nil
	}
	a.cancel()
	a.copyMu.Lock()
	a.dropCopyLocked()
	a.copyMu.Unlock()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.server != nil {
		_ = a.server.Close()
	}
	var errs []error
	for _, r := range a.receivers {
		if err := r.receiver.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := a.root.Close(); err != nil {
		errs = append(errs, err)
	}
	if a.lock != nil {
		if err := a.lock.Unlock(); err != nil {
			errs = append(errs, err)
		}
	}
	if a.identityUse != nil {
		if err := a.identityUse.Unlock(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// net/http reports TLS failures here, including ones before VerifyConnection.
// Never retain arbitrary bytes from a malformed or unauthenticated ClientHello.
type handshakeLogWriter struct {
	record func(netip.Addr, string, bool)
}

func (w handshakeLogWriter) Write(p []byte) (int, error) {
	const prefix = "http: TLS handshake error from "
	line := strings.TrimSpace(string(p))
	if !strings.HasPrefix(line, prefix) {
		log.Print(line)
		return len(p), nil
	}
	address, reason, ok := strings.Cut(strings.TrimPrefix(line, prefix), ": ")
	addr, err := netip.ParseAddrPort(address)
	if !ok || err != nil {
		return len(p), nil
	}
	switch reason {
	case "metadata_agent_stopped", "metadata_refresh_timeout", "metadata_refresh_failed", "metadata_not_ready", "declaration_missing", "member_not_in_netmap", "metadata_unavailable", "scope_changed", "declaration_expired", "no_verified_declaration",
		"invalid file transfer declaration", "invalid file transfer lease", "invalid file transfer certificate", "invalid file transfer certificate usage or lifetime", "invalid file transfer possession proof", "invalid assistance capability proof",
		"transfer certificate fingerprint mismatch", "transfer certificate expired or not yet valid", "exactly one pinned transfer certificate required",
		"tls: client didn't provide a certificate", "remote error: tls: bad certificate", "remote error: tls: unknown certificate authority", "EOF", "unexpected EOF":
	default:
		reason = "other_tls_handshake_failure"
	}
	w.record(addr.Addr().Unmap(), reason, false)
	return len(p), nil
}

func (a *Agent) ClipboardReceiving() bool { return a.clipboardReceiving.Load() && !a.closed.Load() }
func (a *Agent) SetClipboardReceiving(enabled bool) error {
	if a.closed.Load() {
		return errors.New("agent closed")
	}
	a.clipboardReceiving.Store(enabled)
	if !enabled {
		a.mu.Lock()
		defer a.mu.Unlock()
		for _, r := range a.receivers {
			if r.grant.ClipboardTransport {
				r.receiver.Interrupt()
				_ = r.receiver.CancelIncomplete()
			}
		}
	}
	return nil
}
