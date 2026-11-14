package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/calabinet/calabi/apps/client/internal/assistance"
	"github.com/calabinet/calabi/apps/client/internal/filecontrol"
	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	"golang.org/x/sync/singleflight"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type handshakeEvent struct {
	Time   int64  `json:"time_unix_ms"`
	Action string `json:"action"`
	Detail string `json:"error"`
	Level  string `json:"level"`
}
type desktopFileAgent struct {
	shellPasteLive        atomic.Bool
	shellPasteMarker      string // protected by opMu; display-only pending-request suppression
	metadataRefresh       singleflight.Group
	handshakeMu           sync.Mutex
	handshakes            []handshakeEvent
	assistController      assistance.Controller
	assistInFlight        atomic.Bool
	assistUsed            atomic.Int64
	background            sync.WaitGroup
	managed               *fileServiceState // protected by opMu
	closeOnce             sync.Once
	console               string
	ctx                   context.Context
	cancel                context.CancelFunc
	dir                   string
	identity              *filetransfer.Identity
	identityError         error
	renewAfter            time.Time            // protected by opMu
	renewRestore          *renewReceptionModes // protected by opMu
	lease                 string
	mu                    sync.RWMutex // live metadata only, never held during disk IO or HTTP
	view                  filecontrol.Snapshot
	updated               time.Time
	metaError             string
	opMu                  sync.Mutex // main/stdin owns UI actions; poll loop only snapshots workspace pointer
	w                     *filetransfer.Workspace
	scope                 string
	wEpoch                int64
	wMu                   sync.RWMutex
	publishMu             sync.Mutex
	published             string
	publishedRegistration atomic.Int64
	stageMu               sync.Mutex
	stageCancel           context.CancelFunc
	stageGeneration       uint64
	stageError            string
}
type fileAction struct {
	SSHPreview  string             `json:"ssh_preview,omitempty"`
	RDPPreview  string             `json:"rdp_preview,omitempty"`
	SSHPort     uint16             `json:"ssh_port,omitempty"`
	RDPPort     uint16             `json:"rdp_port,omitempty"`
	RDPProfile  string             `json:"rdp_profile,omitempty"`
	RDPAccount  string             `json:"rdp_account,omitempty"`
	RDPName     string             `json:"rdp_name,omitempty"`
	CopyRequest string             `json:"copy_request,omitempty"`
	Paths       []string           `json:"paths,omitempty"`
	Assist      assistance.Command `json:"assist,omitempty"`
	Owner       uint64             `json:"owner,omitempty"`
	Action      string             `json:"action"`
	Peer        string             `json:"peer"`
	ID          string             `json:"id"`
	IDs         []string           `json:"ids"`
	Enabled     bool               `json:"enabled"`
	Accept      bool               `json:"accept"`
	Confirmed   bool               `json:"confirmed"`
	AutoSave    bool               `json:"auto_save"`
}

func newDesktopFileAgent(ctx context.Context, console string) (*desktopFileAgent, error) {
	if _, err := filecontrol.EndpointForConsole(console); err != nil {
		return nil, err
	}
	account, err := user.Current()
	if err != nil {
		return nil, err
	}
	if inServiceManager || account.Uid == "0" || account.Uid == "S-1-5-18" || account.Uid == "S-1-5-19" || account.Uid == "S-1-5-20" {
		return nil, errors.New("file agent must run as an ordinary OS user, not root or a system service")
	}
	cache, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(cache, "Calabi", "file-agent")
	if err := filetransfer.PrivateDirectory(dir); err != nil {
		return nil, err
	}
	id, identityErr := filetransfer.LoadManagedIdentity(dir)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	b, err := root.ReadFile("agent-lease")
	if errors.Is(err, os.ErrNotExist) {
		var token [32]byte
		if _, err := rand.Read(token[:]); err != nil {
			return nil, err
		}
		b = []byte(hex.EncodeToString(token[:]))
		f, err := root.OpenFile("agent-lease", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		_, err = f.Write(b)
		if err == nil {
			err = f.Sync()
		}
		ce := f.Close()
		if err != nil {
			return nil, err
		}
		if ce != nil {
			return nil, ce
		}
	} else if err != nil {
		return nil, err
	}
	if len(b) != 64 {
		return nil, errors.New("invalid private agent lease")
	}
	agentCtx, cancel := context.WithCancel(ctx)
	d := &desktopFileAgent{ctx: agentCtx, cancel: cancel, dir: dir, identity: id, identityError: identityErr, lease: string(b)}
	d.console = console
	d.poll()
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		if err := d.configureManaged(""); err != nil {
			d.close()
			return nil, err
		}
	}
	d.startShellPaste()
	context.AfterFunc(agentCtx, d.close)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-d.ctx.Done():
				return
			case <-ticker.C:
				d.refreshSnapshot()
			}
		}
	}()
	go d.loop()
	return d, nil
}
func (d *desktopFileAgent) refreshSnapshot() {
	started := time.Now()
	view, err := filecontrol.Call(d.ctx, d.console, filecontrol.Request{Op: "snapshot", Lease: d.lease})
	d.mu.Lock()
	defer d.mu.Unlock()
	if started.Before(d.updated) {
		return
	}
	d.updated = started
	if err != nil {
		d.view = filecontrol.Snapshot{}
		d.metaError = err.Error()
	} else {
		d.view = view
		d.metaError = ""
	}
}
func (d *desktopFileAgent) poll() {
	d.refreshSnapshot()
	d.maintainSnapshot()
}
func (d *desktopFileAgent) assistActive() bool {
	return d.assistInFlight.Load() || time.Now().Unix()-d.assistUsed.Load() < 10
}
func (d *desktopFileAgent) maintainSnapshot() {
	view, err := d.metadata()
	if err == nil && view.Ready {
		d.wMu.RLock()
		w := d.w
		d.wMu.RUnlock()
		if w != nil {
			active := w.Agent.Receiving() || w.Agent.Assisting() || w.Agent.ClipboardReceiving() || w.NeedsControlSession() || d.assistActive()
			if active && (!view.OwnsLease || view.Registration != d.publishedRegistration.Load()) {
				if err := d.publish(w, true); err != nil && strings.Contains(err.Error(), "another local user session") && (w.Agent.Receiving() || w.Agent.Assisting() || w.Agent.ClipboardReceiving()) {
					_ = w.Agent.StopServing()
				}
			}
			w.Agent.ApplyKnownRelayLimit(view.RelayKbps)
			_ = w.Agent.Revalidate(func(key string, ip netip.Addr) bool {
				for _, m := range view.Members {
					if m.DeviceKey == key && m.IP == ip.String() {
						return m.Incoming
					}
				}
				return false
			})
		}
	}
}
func (d *desktopFileAgent) loop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	n := 0
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.renewIdentityWhenIdle()
			d.maintainSnapshot()
			d.reconcileManaged()
			d.reconcileClipboard()
			n++
			if n%20 == 0 {
				d.wMu.RLock()
				w := d.w
				d.wMu.RUnlock()
				if w != nil {
					active := w.Agent.Receiving() || w.Agent.Assisting() || w.Agent.ClipboardReceiving() || w.NeedsControlSession() || d.assistActive()
					for _, j := range w.Jobs() {
						active = active || j.State == "sending"
					}
					if active {
						_ = d.publish(w, true)
					} else {
						_ = d.publish(w, false)
					}
				}
			}
		}
	}
}

func (d *desktopFileAgent) metadata() (filecontrol.Snapshot, error) {
	if err := d.ctx.Err(); err != nil {
		return filecontrol.Snapshot{}, err
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if !d.view.Ready || time.Since(d.updated) > 2*time.Second {
		return filecontrol.Snapshot{}, errors.New("live file metadata unavailable: " + d.metaError)
	}
	return d.view, nil
}

// An expired cache cannot authorize traffic. If maintenance delayed polling,
// ask the privileged local daemon for a fresh decision before rejecting.
func (d *desktopFileAgent) inboundMetadata() (filecontrol.Snapshot, error) {
	v, err := d.metadata()
	if err == nil {
		return v, nil
	}
	if d.ctx.Err() != nil {
		return filecontrol.Snapshot{}, errors.New("metadata_agent_stopped")
	}
	value, err, _ := d.metadataRefresh.Do("inbound", func() (any, error) {
		ctx, cancel := context.WithTimeout(d.ctx, 650*time.Millisecond)
		defer cancel()
		snap, err := filecontrol.Call(ctx, d.console, filecontrol.Request{Op: "snapshot", Lease: d.lease})
		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				return nil, errors.New("metadata_refresh_timeout")
			}
			return nil, errors.New("metadata_refresh_failed")
		}
		if !snap.Ready {
			return nil, errors.New("metadata_not_ready")
		}
		return snap, nil
	})
	if err != nil {
		return filecontrol.Snapshot{}, err
	}
	return value.(filecontrol.Snapshot), nil
}

func (d *desktopFileAgent) ensure() (*filetransfer.Workspace, error) {
	if d.identityError != nil {
		return nil, d.identityError
	}
	if d.identity == nil {
		return nil, errors.New("file identity unavailable")
	}
	view, err := d.metadata()
	if err != nil {
		return nil, err
	}
	scope := view.Scope + "/" + d.identity.HistoryID()
	d.wMu.RLock()
	w, oldScope, oldEpoch := d.w, d.scope, d.wEpoch
	d.wMu.RUnlock()
	if w != nil && oldScope == scope && oldEpoch == view.ReceiveEpoch && w.Agent.Alive() {
		return w, nil
	}
	if w != nil {
		d.cancelPreparation()
		if oldScope != scope || oldEpoch != view.ReceiveEpoch {
			_ = w.Agent.SetReceiving(false)
			w.Revoke()
		}
		_ = w.Close()
	}
	h := sha256.Sum256([]byte(scope))
	dir := filepath.Join(d.dir, hex.EncodeToString(h[:]))
	if err := filetransfer.PrivateDirectory(dir); err != nil {
		return nil, err
	}
	local, err := netip.ParseAddr(view.Overlay)
	if err != nil {
		return nil, err
	}
	lookup := func(ip netip.Addr) (filetransfer.Grant, error) {
		v, err := d.inboundMetadata()
		if err != nil {
			return filetransfer.Grant{}, err
		}
		if v.Scope != view.Scope || v.ReceiveEpoch != view.ReceiveEpoch {
			return filetransfer.Grant{}, errors.New("scope_changed")
		}
		return lookupHandshakePeer(v, ip)
	}
	resolve := func(ip netip.Addr) (filetransfer.Grant, bool) { g, err := lookup(ip); return g, err == nil }
	incoming := func(ip netip.Addr, port uint16) bool {
		v, err := d.inboundMetadata()
		if err != nil || v.Scope != view.Scope || v.ReceiveEpoch != view.ReceiveEpoch || port != 17401 {
			return false
		}
		for _, p := range v.Peers {
			if p.Grant.Peer.IP == ip && time.Now().Unix() < p.ExpiresUnix {
				return p.Incoming
			}
		}
		return false
	}
	authority := func() bool {
		v, err := d.inboundMetadata()
		return err == nil && v.Scope == view.Scope && v.ReceiveEpoch == view.ReceiveEpoch && v.OwnsLease
	}
	host := assistance.NewHost()
	host.OnWindowExit = func(key, reason string) {
		d.mu.RLock()
		var ip netip.Addr
		for _, m := range d.view.Members {
			if m.DeviceKey == key {
				ip, _ = netip.ParseAddr(m.IP)
				break
			}
		}
		d.mu.RUnlock()
		level := "WARN"
		if reason == "stopped" || reason == "declined" {
			level = "INFO"
		}
		d.recordPeerEvent(ip, reason, "assist_session", level)
	}
	serveAssist := func(ctx context.Context, g filetransfer.Grant, w http.ResponseWriter, r *http.Request) {
		if runtime.GOOS != "windows" {
			http.NotFound(w, r)
			return
		}
		label := g.Peer.IP.String()
		if v, e := d.metadata(); e == nil {
			for _, p := range v.Peers {
				if p.Grant.DeviceKey == g.DeviceKey && p.Name != "" {
					label = p.Name + " · " + label
					break
				}
			}
		}
		host.Serve(ctx, g.DeviceKey, label, w, r)
	}
	w, err = filetransfer.NewWorkspace(filetransfer.AgentConfig{ClipboardPeer: d.clipboardPeer, AssistDenialLog: func(ip netip.Addr, reason string) { d.recordPeerEvent(ip, reason, "assist_http", "WARN") }, HandshakeLookup: lookup, HandshakeLog: d.recordHandshake, Assist: serveAssist, Authority: authority, Identity: d.identity, Directory: dir, Scope: scope, LocalIP: local, Port: 17401, Kbps: filetransfer.DefaultDeviceKbps, MaxBytes: 8 << 30, Resolve: resolve, Incoming: incoming})
	if err != nil {
		return nil, err
	}
	w.Agent.ApplyKnownRelayLimit(view.RelayKbps)
	d.wMu.Lock()
	if err := d.ctx.Err(); err != nil {
		d.wMu.Unlock()
		w.Close()
		return nil, err
	}
	d.w = w
	d.scope = scope
	d.wEpoch = view.ReceiveEpoch
	d.wMu.Unlock()
	return w, nil
}
func (d *desktopFileAgent) publish(w *filetransfer.Workspace, active bool) error {
	return d.publishContext(d.ctx, w, active)
}
func (d *desktopFileAgent) publishContext(ctx context.Context, w *filetransfer.Workspace, active bool) error {
	d.publishMu.Lock()
	defer d.publishMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	view, err := d.metadata()
	if err != nil && !active {
		d.mu.RLock()
		view = d.view
		d.mu.RUnlock()
		if view.Scope != "" {
			err = nil
		}
	}
	if err != nil {
		return err
	}
	d.wMu.RLock()
	current, scope := d.w, d.scope
	d.wMu.RUnlock()
	if w != current || d.identity == nil || scope != view.Scope+"/"+d.identity.HistoryID() {
		return errors.New("file workspace scope changed")
	}
	req := filecontrol.Request{Op: "publish", Scope: view.Scope, Lease: d.lease}
	req.ClipboardListening = active && w.Agent.ClipboardReceiving()
	if active {
		key, err := meshproto.ParseNodeKey(view.NodeKey)
		if err != nil {
			return err
		}
		req.Info, err = d.identity.DesktopDeclaration(key, 17401, w.Agent.Receiving(), w.Agent.Assisting())
		if err != nil {
			return err
		}
	} else if d.published != view.Scope {
		return nil
	}
	callCtx := ctx
	if !active {
		var cancel context.CancelFunc
		callCtx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
	}
	started := time.Now()
	updated, callErr := filecontrol.Call(callCtx, d.console, req)
	err = callErr
	if err == nil {
		d.mu.Lock()
		if !started.Before(d.updated) {
			d.view = updated
			d.updated = started
			d.metaError = ""
		}
		d.mu.Unlock()
		if active {
			d.published = view.Scope
			d.publishedRegistration.Store(view.Registration)
		} else {
			d.published = ""
			d.publishedRegistration.Store(0)
		}
	}
	return err
}
func lookupHandshakePeer(v filecontrol.Snapshot, ip netip.Addr) (filetransfer.Grant, error) {
	for _, p := range v.Peers {
		if p.Grant.Peer.IP == ip {
			if time.Now().Unix() >= p.ExpiresUnix {
				return filetransfer.Grant{}, errors.New("declaration_expired")
			}
			return p.Grant, nil
		}
	}
	for _, m := range v.Members {
		if m.IP == ip.String() {
			if m.DeclarationError != "" {
				return filetransfer.Grant{}, errors.New(m.DeclarationError)
			}
			return filetransfer.Grant{}, errors.New("no_verified_declaration")
		}
	}
	return filetransfer.Grant{}, errors.New("member_not_in_netmap")
}
func (d *desktopFileAgent) recordHandshake(ip netip.Addr, reason string, verified bool) {
	level := "WARN"
	if verified {
		level = "INFO"
	}
	d.recordPeerEvent(ip, reason, "peer_tls", level)
}
func (d *desktopFileAgent) recordPeerEvent(ip netip.Addr, reason, action, level string) {
	d.handshakeMu.Lock()
	defer d.handshakeMu.Unlock()
	if len(d.handshakes) == 64 {
		d.handshakes = d.handshakes[1:]
	}
	d.handshakes = append(d.handshakes, handshakeEvent{time.Now().UnixMilli(), action, "source=" + ip.String() + " reason=" + reason, level})
}

func (d *desktopFileAgent) handle(a fileAction) (any, error) {
	if a.Action == "mesh_copy_rpc" {
		fields := strings.Fields(a.CopyRequest)
		if len(a.CopyRequest) > 20000 || len(fields) == 0 || !strings.HasPrefix(fields[0], "mesh_") {
			return nil, errors.New("invalid clipboard request")
		}
		return map[string]string{"reply": d.meshPasteRequest(fields, a.ID)}, nil
	}

	d.opMu.Lock()
	defer d.opMu.Unlock()
	if a.Action == "receiving" || a.Action == "assist_receiving" || a.Action == "clipboard_receiving" || a.Action == "service_settings" || a.Action == "identity_reset" || a.Action == "identity_renew" || a.Action == "revoke" {
		d.renewRestore = nil
	}
	if a.Action == "assist" && a.Assist.Op == "availability" {
		v, err := d.metadata()
		if err == nil {
			for _, p := range v.Peers {
				if p.Grant.DeviceKey == a.Peer && p.Grant.Assistance && p.ExpiresUnix > time.Now().Unix() {
					return assistance.Reply{State: "available"}, nil
				}
			}
		}
		return assistance.Reply{State: "unavailable"}, nil
	}
	if a.Action == "rdp_target" || a.Action == "rdp_history" || a.Action == "rdp_record" || a.Action == "rdp_preview" {
		return d.rdpProfileAction(a)
	}
	if (runtime.GOOS == "windows" || runtime.GOOS == "darwin") && (a.Action == "ssh_target" || a.Action == "ssh_history" || a.Action == "ssh_record" || a.Action == "ssh_preview") {
		return d.sshAction(a)
	}
	if a.Action == "handshake_diagnostics" {
		d.handshakeMu.Lock()
		defer d.handshakeMu.Unlock()
		return append([]handshakeEvent{}, d.handshakes...), nil
	}
	if a.Action == "identity_status" || a.Action == "identity_renew" || a.Action == "identity_reset" {
		if a.Action != "identity_status" {
			if !a.Confirmed {
				return nil, errors.New("confirm identity maintenance: reception stops and unfinished transfers are cancelled; completed files and sources are retained")
			}
			if err := d.maintainIdentity(strings.TrimPrefix(a.Action, "identity_")); err != nil {
				return nil, err
			}
		}
		return d.identitySnapshot(), nil
	}
	if a.Action == "revoke" {
		var saveErr error
		if d.managed != nil {
			d.managed.settings.Receiving = false
			d.managed.settings.Assistance = false
			saveErr = d.saveServiceSettings()
		}
		d.cancelPreparation()
		d.wMu.RLock()
		current := d.w
		d.wMu.RUnlock()
		if current != nil {
			_ = current.Agent.StopServing()
			current.Revoke()
			_ = d.publish(current, false)
		}
		return map[string]bool{"ok": saveErr == nil}, saveErr
	}
	if a.Action == "service_settings" {
		if d.managed == nil || d.managed.directory == "" {
			return nil, errors.New("managed file service required")
		}
		d.managed.settings.AutoSave = a.AutoSave
		if err := d.saveServiceSettings(); err != nil {
			return nil, err
		}
	}
	w, err := d.ensure()
	if err != nil {
		if a.Action == "assist" {
			d.assistController.Suspend()
		}
		if (a.Action == "assist_receiving" || a.Action == "receiving") && !a.Enabled {
			d.wMu.RLock()
			old := d.w
			d.wMu.RUnlock()
			if old != nil {
				_ = old.Agent.StopServing()
			} // Metadata unavailable: neither service can authorize peers.
			if d.managed != nil {
				if a.Action == "receiving" {
					d.managed.settings.Receiving = false
				} else {
					d.managed.settings.Assistance = false
				}
				if e := d.saveServiceSettings(); e != nil {
					return nil, e
				}
			}
			state := d.identitySnapshot()
			state["service"] = d.managedSnapshot()
			return state, nil
		}
		if a.Action == "snapshot" || a.Action == "service_settings" {
			state := d.identitySnapshot()
			state["unavailable_reason"] = err.Error()
			state["service"] = d.managedSnapshot()
			return state, nil
		}
		return nil, err
	}
	result := func() map[string]any {
		v, _ := d.metadata()
		d.stageMu.Lock()
		preparing, preparationError := d.stageCancel != nil, d.stageError
		d.stageMu.Unlock()
		var owned []string
		if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
			for _, m := range v.Members {
				if m.CanRDPLogin() && m.IP != v.Overlay {
					owned = append(owned, m.DeviceKey)
				}
			}
		}
		return map[string]any{"rdp_paste_marker": d.shellPasteMarker, "rdp_targets": owned, "available": true, "assist_supported": runtime.GOOS == "windows", "assist_receiving": w.Agent.Assisting(), "preparing": preparing, "preparation_error": preparationError, "receiving": w.Agent.Receiving(), "peers": v.Peers, "received": w.Agent.List(), "jobs": w.Jobs(), "sources": w.Staged(), "identity": filetransfer.ReadIdentityStatus(d.dir), "service": d.managedSnapshot()}
	}
	switch a.Action {
	case "assist":
		if a.Assist.Op == "request" {
			d.assistUsed.Store(time.Now().Unix())
			if err := d.publish(w, true); err != nil {
				return nil, err
			}
		}
		v, err := d.metadata()
		if err != nil {
			d.assistController.Suspend()
			return nil, err
		}
		local, err := netip.ParseAddr(v.Overlay)
		if err != nil {
			d.assistController.Suspend()
			return nil, err
		}
		for _, p := range v.Peers {
			g := p.Grant
			if g.DeviceKey == a.Peer && g.Assistance && p.ExpiresUnix > time.Now().Unix() {
				d.assistUsed.Store(time.Now().Unix())
				route := assistance.Route{Local: local, Remote: g.Peer.IP, Port: g.Port, Scope: v.Scope, Device: g.DeviceKey, LocalPin: d.identity.Fingerprint, PeerPin: g.Peer.Fingerprint}
				d.assistInFlight.Store(true)
				defer func() { d.assistUsed.Store(time.Now().Unix()); d.assistInFlight.Store(false) }()
				recoverFrame := func(ctx context.Context, announce bool) error {
					cur, e := d.metadata()
					if e != nil {
						return e
					}
					if cur.Scope == v.Scope && cur.Overlay == v.Overlay && cur.NodeKey == v.NodeKey && cur.ReceiveEpoch == v.ReceiveEpoch {
						for _, peer := range cur.Peers {
							grant := peer.Grant
							if grant.DeviceKey == g.DeviceKey && grant.Peer == g.Peer && grant.Port == g.Port && grant.Assistance && peer.ExpiresUnix > time.Now().Unix() {
								if announce {
									return d.publishContext(ctx, w, true)
								}
								return nil
							}
						}
					}
					return errors.New("target desktop transport unavailable")
				}
				reply, err := d.assistController.CallWithFrameRecovery(d.ctx, route, d.identity.ClientTLS(g.Peer), a.Assist, recoverFrame)
				reply.LocalSplitFrame = (runtime.GOOS == "darwin" || runtime.GOOS == "windows") && a.Assist.Op == "request" && reply.FrameDelta && err == nil
				return reply, err
			}
		}
		d.assistController.Suspend()
		return nil, errors.New("target desktop transport unavailable")
	case "snapshot", "service_settings":
		return result(), nil
	case "assist_receiving", "receiving":
		assist := a.Action == "assist_receiving"
		if assist && runtime.GOOS != "windows" {
			return nil, errors.New("Windows desktop required")
		}
		if d.managed != nil {
			settings := &d.managed.settings
			if settings.Scope != d.scope || settings.Epoch != d.wEpoch {
				settings.Receiving = false
				settings.Assistance = false
			}
			settings.Scope, settings.Epoch = d.scope, d.wEpoch
			if assist {
				settings.Assistance = a.Enabled
			} else {
				settings.Receiving = a.Enabled
			}
			if e := d.saveServiceSettings(); e != nil {
				if !a.Enabled {
					return nil, errors.Join(e, d.setInbound(w, assist, false))
				}
				return nil, e
			}
		}
		err = d.setInbound(w, assist, a.Enabled)
	case "mesh_copy_start", "mesh_copy_renew", "mesh_copy_end":
		if a.Action == "mesh_copy_renew" {
			return nil, w.Agent.CopyRenew(d.ctx, a.ID)
		}
		if a.Action == "mesh_copy_end" {
			w.Agent.CopyClose(d.ctx, a.ID)
			return nil, nil
		}
		v, e := d.metadata()
		if e != nil || !v.Ready {
			return nil, errors.New("mesh metadata unavailable")
		}
		if a.RDPProfile != "" && a.RDPProfile != rdpProfile(v) {
			return nil, errors.New("remote login profile changed")
		}
		for _, member := range v.Members {
			if member.OwnWindows && member.DeviceKey == a.Peer && member.IP != v.Overlay {
				ip, e := netip.ParseAddr(member.IP)
				if e != nil {
					return nil, e
				}
				id, e := w.Agent.CopyStart(d.ctx, ip)
				return map[string]string{"session": id}, e
			}
		}
		return nil, errors.New("owned Windows target required")
	case "rdp_copy_send", "rdp_copy_status":
		return d.rdpCopyAction(w, a)
	case "pick":
		d.stageMu.Lock()
		preparing := d.stageCancel != nil
		d.stageMu.Unlock()
		if preparing {
			return nil, errors.New("another file preparation is active")
		}
		var paths []string
		paths, err = pickTransferFiles(a.Owner)
		if err == nil {
			d.startPreparation(w, paths)
		}
	case "cancel_preparing":
		d.cancelPreparation()
		w.CancelPreparation()
	case "send", "resume":
		var ip netip.Addr
		if a.Action == "resume" && a.Peer == "" {
			for _, j := range w.Jobs() {
				if j.ID == a.ID {
					a.Peer = j.PeerIP
					break
				}
			}
		}
		ip, err = netip.ParseAddr(a.Peer)
		if err == nil {
			err = d.publish(w, true)
		}
		if err == nil {
			resume := ""
			if a.Action == "resume" {
				resume = a.ID
			}
			_, err = w.Send(ip, a.IDs, resume)
		}
	case "decide":
		err = w.Agent.Decide(a.IDs, a.Accept)
	case "pause":
		err = w.Pause(a.ID)
	case "cancel":
		err = w.Cancel(a.ID)
	case "cancel_receive":
		err = w.Agent.Cancel(a.ID)
	case "pause_receive", "resume_receive":
		err = w.Agent.SetReceivePaused(a.ID, a.Action == "pause_receive")
	case "forget_receive":
		err = w.Agent.Forget(a.ID)
	case "forget_job":
		err = w.ForgetJob(a.ID)
	case "forget_source":
		err = w.ForgetSource(a.ID)
	case "save":
		var path string
		var name string
		for _, row := range w.Agent.List() {
			if row.Transfer.ID == a.ID && row.Transfer.State == "completed" {
				name = row.Transfer.Name
				break
			}
		}
		if name == "" {
			err = errors.New("verified file not found")
			break
		}
		path, err = pickTransferDestination(name, a.Owner)
		if err == nil && path != "" {
			err = saveVerifiedFileReplacing(w, a.ID, path)
		}
	default:
		err = errors.New("unknown file action")
	}
	if err != nil {
		return nil, err
	}
	return result(), nil
}
func (d *desktopFileAgent) close() {
	d.closeOnce.Do(func() {
		d.opMu.Lock()
		d.cancel()
		d.cancelPreparation()
		d.wMu.RLock()
		w := d.w
		d.wMu.RUnlock()
		d.opMu.Unlock()
		if w != nil {
			// Process exit checkpoints durable tasks. Explicit logout, identity
			// maintenance and scope changes use Revoke separately.
			_ = w.Close()
			_ = d.publishContext(context.Background(), w, false)
		}
		d.background.Wait()
	})
}

func (d *desktopFileAgent) setReceiving(w *filetransfer.Workspace, enabled bool) error {
	return d.setInbound(w, false, enabled)
}
func (d *desktopFileAgent) setInbound(w *filetransfer.Workspace, assistance, enabled bool) error {
	return d.setInboundMode(w, assistance, false, enabled)
}
func (d *desktopFileAgent) setInboundMode(w *filetransfer.Workspace, assistance, clipboard, enabled bool) error {
	set, other := w.Agent.SetReceiving, w.Agent.Assisting() || w.Agent.ClipboardReceiving()
	if assistance {
		set, other = w.Agent.SetAssistance, w.Agent.Receiving() || w.Agent.ClipboardReceiving()
	}
	if clipboard {
		set, other = w.Agent.SetClipboardReceiving, w.Agent.Receiving() || w.Agent.Assisting()
	}
	if !enabled {
		var err error
		if other {
			err = set(false)
		} else {
			err = w.Agent.StopServing()
		}
		active := other || w.NeedsControlSession() || d.assistActive()
		for _, j := range w.Jobs() {
			active = active || j.State == "sending"
		}
		return errors.Join(err, d.publish(w, active))
	}
	wasEnabled := w.Agent.Receiving()
	if clipboard {
		wasEnabled = w.Agent.ClipboardReceiving()
	}
	if assistance {
		wasEnabled = w.Agent.Assisting()
	}
	if other || wasEnabled {
		if err := set(true); err != nil {
			return err
		}
		err := d.publish(w, true)
		if err != nil && !wasEnabled {
			_ = set(false)
		}
		return err
	}
	// Claim the local user lease with reception still off. A failed claim must
	// never briefly accept a stale resume token into a different user's slot.
	if err := d.publish(w, true); err != nil {
		return err
	}
	v, err := d.metadata()
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(v.Overlay)
	if err != nil {
		return err
	}
	addr, _ := filetransfer.Address(ip, 17401)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		_ = d.publish(w, false)
		return err
	}
	served, err := w.Agent.Serve(listener)
	if err != nil {
		listener.Close()
		_ = d.publish(w, false)
		return err
	}
	go func() {
		err := <-served
		if err != nil && !errors.Is(err, http.ErrServerClosed) && d.ctx.Err() == nil {
			d.mu.Lock()
			d.metaError = err.Error()
			d.mu.Unlock()
		}
	}()
	if err := set(true); err != nil {
		_ = w.Agent.StopServing()
		_ = d.publish(w, false)
		return err
	}
	if err := d.publish(w, true); err != nil {
		_ = w.Agent.StopServing()
		_ = d.publish(w, false)
		return err
	}
	return nil
}

func (d *desktopFileAgent) cancelPreparation() {
	d.stageMu.Lock()
	cancel := d.stageCancel
	d.stageGeneration++
	d.stageCancel = nil
	d.stageMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (d *desktopFileAgent) startPreparation(w *filetransfer.Workspace, paths []string) {
	if len(paths) == 0 {
		return
	}
	ctx, cancel := context.WithCancel(w.Context())
	d.stageMu.Lock()
	d.stageGeneration++
	generation := d.stageGeneration
	d.stageCancel = cancel
	d.stageError = ""
	d.stageMu.Unlock()
	go func() {
		var stageErr error
		defer cancel()
		defer func() {
			d.stageMu.Lock()
			defer d.stageMu.Unlock()
			if d.stageGeneration == generation {
				d.stageCancel = nil
				if stageErr != nil {
					d.stageError = stageErr.Error()
				}
			}
		}()
		for _, path := range paths {
			if err := ctx.Err(); err != nil {
				stageErr = err
				return
			}
			_, err := w.ReferenceLocal(ctx, path)
			if err != nil {
				stageErr = err
				return
			}
		}
	}()
}

func runMeshFiles(args []string) int {
	if len(args) > 0 && args[0] == "firewall" {
		return runMeshFileFirewall(args[1:])
	}
	if len(args) > 0 && args[0] == "service" {
		return runFileService(args[1:])
	}
	fs := flag.NewFlagSet("mesh files", flag.ContinueOnError)
	stdio := fs.Bool("stdio", false, "private JSON-lines protocol for desktop shell")
	background := fs.Bool("background", false, "run the installed Windows user file agent")
	attach := fs.Bool("attach", false, "forward --stdio to the installed Windows user file agent")
	console := fs.String("console", "http://127.0.0.1:7400", "exact supervised daemon console URL")
	web := fs.String("web", "", "Linux browser control: explicit loopback or this device's overlay IP:port")
	webURL := fs.Bool("web-url", false, "issue a five-minute single-use pairing link for the running browser file agent")
	webDir := fs.String("web-dir", "", "existing directory for browser file selection and export")
	if fs.Parse(args) != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: calabi mesh files [--stdio | --web IP:port --web-dir directory] [--console http://127.0.0.1:7400]")
		return 2
	}
	if *background || *attach {
		if runtime.GOOS != "windows" || (*background && *attach) || *attach != *stdio ||
			*console != "http://127.0.0.1:7400" || *web != "" || *webURL || *webDir != "" {
			fmt.Fprintln(os.Stderr, "installed Windows file agent requires --background or --stdio --attach and the default console")
			return 2
		}
		return runBackgroundFileAgent(*attach, *console)
	}
	if (*web != "" && (runtime.GOOS != "linux" || *stdio || *webDir == "")) || (*web == "" && *webDir != "") {
		fmt.Fprintln(os.Stderr, "browser control requires Linux, --web IP:port and --web-dir; it cannot be combined with --stdio")
		return 2
	}
	if *webURL {
		if *stdio || *web != "" || *webDir != "" {
			fmt.Fprintln(os.Stderr, "--web-url cannot start a file agent")
			return 2
		}
		link, err := standaloneBrowserURL()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println(link)
		return 0
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if !*stdio && *web == "" {
		if handled, code := connectFileConsole(ctx, *console); handled {
			return code
		}
	}
	d, err := newDesktopFileAgent(ctx, *console)
	if err != nil {
		if *stdio {
			_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"error": "Cannot initialize file agent: " + err.Error()})
		} else {
			fmt.Fprintln(os.Stderr, err)
		}
		return 1
	}
	defer d.close()
	if *web != "" {
		if err := d.serveBrowser(*web, *webDir); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	if !*stdio {
		return runFileConsole(d.ctx, d.handleConsoleAction)
	}
	return serveFileActions(os.Stdin, os.Stdout, d.handle)
}

// Only allowlisted actions cross the private desktop RPC channel. Native
// dialogs and file operations run in the logged-in user's file agent.
func serveFileActions(input io.Reader, output io.Writer, handle func(fileAction) (any, error)) int {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 8192), 256<<10)
	writer := json.NewEncoder(output)
	for scanner.Scan() {
		var action fileAction
		dec := json.NewDecoder(strings.NewReader(scanner.Text()))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&action); err != nil {
			_ = writer.Encode(map[string]any{"error": "invalid file action"})
			continue
		}
		if len(scanner.Bytes()) > 16<<10 && action.Action != "rdp_preview" && action.Action != "ssh_preview" {
			_ = writer.Encode(map[string]any{"error": "invalid file action"})
			continue
		}
		result, err := handle(action)
		if err != nil {
			result = map[string]any{"error": err.Error()}
		}
		if err := writer.Encode(result); err != nil {
			return 1
		}
	}
	if scanner.Err() != nil && !errors.Is(scanner.Err(), io.EOF) {
		return 1
	}
	return 0
}

func runFileConsole(ctx context.Context, handle func(fileAction) (any, error)) int {
	fmt.Println("File transfers (current OS user). Reception starts off.\nCommands: list | receive on/off | stage <local-path> | export <file-ID> <new-local-path> | pick | send <peer-IP> <source-ID...> | accept/reject <file-ID...> | save <file-ID> | pause/resume/cancel <job-ID> | pause_receive/resume_receive/cancel_receive/forget_receive/forget_job/forget_source <ID> | identity status/renew/reset | quit")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 16<<10)
	stop := context.AfterFunc(ctx, func() { _ = os.Stdin.Close() })
	defer stop()
	for {
		fmt.Print("files> ")
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		args := strings.Fields(line)
		if len(args) == 0 {
			continue
		}
		var a fileAction
		switch args[0] {
		case "quit", "exit":
			return 0
		case "help":
			fmt.Println("list | receive on/off | stage <local-path> | export <file-ID> <new-local-path> | send <peer-IP> <source-ID...> | accept/reject <file-ID...> | pause/resume/cancel <job-ID> | identity status | identity renew confirm | identity reset confirm | quit\nIdentity maintenance stops reception and cancels unfinished transfers across this user's organizations; completed files and staged sources are retained.")
			continue
		case "stage":
			path := strings.TrimSpace(strings.TrimPrefix(line, "stage"))
			if path == "" {
				fmt.Println("use: stage <local-path>; spaces in the path are allowed, no quotes needed")
				continue
			}
			if _, err := handle(fileAction{Action: "console_stage", Paths: []string{path}}); err != nil {
				fmt.Fprintln(os.Stderr, err)
			} else {
				fmt.Println("preparing; use list to read source IDs and errors")
			}
			continue
		case "export":
			if len(args) < 3 {
				fmt.Println("use: export <completed-file-ID> <new-local-path>")
				continue
			}
			path := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(line, "export")), args[1]))
			if _, err := handle(fileAction{Action: "console_export", ID: args[1], Paths: []string{path}}); err != nil {
				fmt.Fprintln(os.Stderr, err)
			} else {
				fmt.Println("verified file saved")
			}
			continue
		case "list", "devices":
			a.Action = "snapshot"
		case "identity":
			if len(args) < 2 || (args[1] != "status" && args[1] != "renew" && args[1] != "reset") {
				fmt.Println("identity status | identity renew confirm | identity reset confirm")
				continue
			}
			a.Action = "identity_" + args[1]
			a.Confirmed = len(args) == 3 && args[2] == "confirm"
		case "receive":
			if len(args) != 2 || (args[1] != "on" && args[1] != "off") {
				fmt.Println("use: receive on/off")
				continue
			}
			a.Action = "receiving"
			a.Enabled = args[1] == "on"
		case "pick":
			a.Action = "pick"
		case "send":
			if len(args) < 3 {
				fmt.Println("use: send <peer-IP> <source-ID...>")
				continue
			}
			a.Action = "send"
			a.Peer = args[1]
			a.IDs = args[2:]
		case "accept", "reject":
			if len(args) < 2 {
				fmt.Println("select file IDs from list")
				continue
			}
			a.Action = "decide"
			a.IDs = args[1:]
			a.Accept = args[0] == "accept"
		case "save", "pause", "resume", "cancel", "cancel_receive", "pause_receive", "resume_receive", "forget_receive", "forget_job", "forget_source":
			if len(args) != 2 {
				fmt.Println("one local transfer/source ID required")
				continue
			}
			a.Action = args[0]
			a.ID = args[1]
		default:
			fmt.Println("unknown command; list shows current local IDs")
			continue
		}
		out, err := handle(a)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		body, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(body))
	}
	return 0
}
