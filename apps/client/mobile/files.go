package mobile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
	"github.com/calabinet/calabi/apps/client/internal/mesh"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type mobileFiles struct {
	contextKey string
	failed     atomic.Bool
	paths      *atomic.Value
	scope      string
	w          *filetransfer.Workspace
	e          *engine
	ctrl       *mesh.Controller
	id         *filetransfer.Identity
	cancel     context.CancelFunc
	done       chan struct{}
	mu         sync.Mutex
	err        string
}

// Caller holds fileMu. Private files and keys stay inside Android's app UID.
func (c *Core) ensureFiles() (*mobileFiles, error) {
	if c.fileTest != nil && c.fileTest.running {
		return nil, errors.New("stop the manually paired file test first")
	}
	if !c.cfg.FileTransferV1 {
		return nil, errors.New("file transfer is disabled in this build")
	}
	e := c.currentEngine()
	if e == nil {
		return c.filesHistory()
	}
	e.mu.Lock()
	ctrl, dp, enr := e.ctrl, e.dp, e.enr
	e.mu.Unlock()
	if ctrl == nil || dp == nil || !ctrl.FileTransferReady() {
		return c.filesHistory()
	}
	st := e.status()
	local, err := netip.ParseAddr(st.Overlay)
	if err != nil || st.State != stateConnected {
		return c.filesHistory()
	}
	if f := c.files; f != nil && f.e == e && f.ctrl == ctrl && f.contextKey == c.fileContext() && f.w.Agent.Alive() && !f.failed.Load() {
		paths := map[string]string{}
		for _, p := range st.Peers {
			paths[p.PublicKey] = p.Path
		}
		f.paths.Store(paths)
		return f, nil
	}
	previousReceiving := false
	previousScope := ""
	if c.files != nil && c.files.e == e {
		previousReceiving = c.files.w.Agent.Receiving()
		previousScope = c.files.scope
	}
	if c.files != nil {
		c.closeFilesLocked(false)
	}
	c.stopFileTestLocked()
	base := filepath.Join(c.cfg.StateDir, "files-v1")
	if err := os.MkdirAll(base, 0700); err != nil {
		return nil, err
	}
	id, err := filetransfer.LoadIdentity(base)
	if err != nil {
		return nil, err
	}
	scope := fmt.Sprintf("%s/%s/%d/%s/%s", enr.CoordAddr, e.selfKey(enr.OrgID), ctrl.FileNodeID(), ctrl.Params.NodeKey.String(), id.HistoryID())
	h := sha256.Sum256([]byte(scope))
	dir := filepath.Join(base, hex.EncodeToString(h[:]))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	current := func() bool {
		if c.currentEngine() != e {
			return false
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		return e.ctrl == ctrl && e.state == stateConnected
	}
	paths := &atomic.Value{}
	currentPaths := map[string]string{}
	for _, p := range st.Peers {
		currentPaths[p.PublicKey] = p.Path
	}
	paths.Store(currentPaths)
	resolve := func(ip netip.Addr) (filetransfer.Grant, bool) {
		if !current() {
			return filetransfer.Grant{}, false
		}
		p, pin, ok := ctrl.FilePeer(ip)
		if !ok {
			return filetransfer.Grant{}, false
		}
		return filetransfer.Grant{Path: paths.Load().(map[string]string)[p.NodeKey.String()], Peer: filetransfer.Peer{IP: ip, Fingerprint: pin}, DeviceKey: p.NodeKey.String(), Port: uint16(p.FileTransfer.Port), Receiving: p.FileTransfer.Receiving}, true
	}
	w, err := filetransfer.NewWorkspace(filetransfer.AgentConfig{Identity: id, Directory: dir, Scope: scope, LocalIP: local, Port: 17401, Kbps: filetransfer.DefaultDeviceKbps, MaxBytes: 8 << 30, Resolve: resolve, Incoming: func(ip netip.Addr, port uint16) bool { return current() && dp.IncomingTCPAllowed(ip, port) }})
	if err != nil {
		return nil, err
	}
	addr, _ := filetransfer.Address(local, 17401)
	w.Agent.ApplyKnownRelayLimit(ctrl.FileRelayLimit())
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		w.Close()
		return nil, fmt.Errorf("file listener: %w", err)
	}
	served, err := w.Agent.Serve(listener)
	if err != nil {
		listener.Close()
		w.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := &mobileFiles{w: w, e: e, ctrl: ctrl, id: id, cancel: cancel, done: make(chan struct{})}
	f.scope = scope
	f.contextKey = c.fileContext()
	f.paths = paths
	if err := c.rememberFiles(f, local.String()); err != nil {
		cancel()
		w.Close()
		return nil, err
	}
	if previousReceiving && previousScope == scope {
		_ = w.Agent.SetReceiving(true)
	}
	c.files = f
	go func() {
		defer close(f.done)
		ticker := time.NewTicker(25 * time.Second)
		defer ticker.Stop()
		publish := func() {
			w.Agent.ApplyKnownRelayLimit(ctrl.FileRelayLimit())
			info, err := id.Declaration(ctrl.Params.NodeKey, 17401, w.Agent.Receiving())
			if err == nil {
				pctx, stop := context.WithTimeout(ctx, 5*time.Second)
				err = ctrl.PublishFileTransfer(pctx, info)
				stop()
			}
			f.mu.Lock()
			if err != nil {
				f.err = err.Error()
			} else {
				f.err = ""
			}
			f.mu.Unlock()
		}
		publish()
		for {
			select {
			case <-ctx.Done():
				return
			case err := <-served:
				f.failed.Store(true)
				f.mu.Lock()
				if err != nil && !errors.Is(err, http.ErrServerClosed) {
					f.err = err.Error()
				}
				f.mu.Unlock()
				return
			case <-ticker.C:
				publish()
			}
		}
	}()
	return f, nil
}

func (c *Core) closeFilesLocked(revoke bool) {
	f := c.files
	if f == nil {
		return
	}
	c.files = nil
	if revoke {
		_ = f.w.Agent.SetReceiving(false)
		f.w.Revoke()
	}
	f.cancel()
	<-f.done
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	if f.ctrl != nil {
		_ = f.ctrl.PublishFileTransfer(ctx, nil)
	}
	cancel()
	_ = f.w.Close()
}
func (c *Core) stopFiles(revoke bool) {
	c.fileMu.Lock()
	defer c.fileMu.Unlock()
	c.closeFilesLocked(revoke)
}

func (c *Core) filesLoop(e *engine) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	defer func() {
		c.fileMu.Lock()
		defer c.fileMu.Unlock()
		if c.files != nil && c.files.e == e {
			c.closeFilesLocked(false)
		}
	}()
	for {
		select {
		case <-e.done:
			return
		case <-ticker.C:
			c.fileMu.Lock()
			if c.currentEngine() == e {
				if f, err := c.ensureFiles(); err == nil && c.filesLive(f) {
					e.mu.Lock()
					dp := e.dp
					e.mu.Unlock()
					_ = f.w.Agent.Revalidate(func(key string, ip netip.Addr) bool {
						return dp != nil && f.ctrl.DeviceKeyForIP(ip) == key && dp.IncomingTCPAllowed(ip, 17401)
					})
				}
			}
			c.fileMu.Unlock()
		}
	}
}

func (c *Core) handleFiles(w http.ResponseWriter, _ *http.Request) {
	c.fileMu.Lock()
	defer c.fileMu.Unlock()
	f, err := c.ensureFiles()
	if err != nil {
		writeJSON(w, 200, map[string]any{"available": false, "error": err.Error(), "peers": []any{}, "received": []any{}, "jobs": []any{}, "sources": []any{}, "identity": filetransfer.ReadIdentityStatus(filepath.Join(c.cfg.StateDir, "files-v1"))})
		return
	}
	peers := []map[string]any{}
	live := c.filesLive(f)
	if live {
		for _, p := range f.ctrl.FilePeers() {
			peers = append(peers, map[string]any{"ip": p.Overlay.String(), "name": p.Name, "receiving": p.FileTransfer.Receiving, "device_key": p.NodeKey.String()})
		}
	}
	f.mu.Lock()
	lastError := f.err
	f.mu.Unlock()
	if !live {
		lastError = "Reconnect to send or receive files. Local records and completed files remain available."
	}
	writeJSON(w, 200, map[string]any{"available": live, "preparing": f.w.Preparing(), "receiving": live && f.w.Agent.Receiving(), "peers": peers, "received": f.w.Agent.List(), "jobs": f.w.Jobs(), "sources": f.w.Staged(), "error": lastError, "identity": filetransfer.ReadIdentityStatus(filepath.Join(c.cfg.StateDir, "files-v1"))})
}
func (c *Core) handleFileAction(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Action    string   `json:"action"`
		ID        string   `json:"id"`
		IDs       []string `json:"ids"`
		Enabled   bool     `json:"enabled"`
		Accept    bool     `json:"accept"`
		Peer      string   `json:"peer"`
		Confirmed bool     `json:"confirmed"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&in); err != nil {
		writeError(w, 400, "invalid file action")
		return
	}
	c.fileMu.Lock()
	defer c.fileMu.Unlock()
	if in.Action == "identity_renew" || in.Action == "identity_reset" {
		if !c.cfg.FileTransferV1 || c.fileContext() == "" {
			writeError(w, 403, "file identity requires a signed-in context")
			return
		}
		if !in.Confirmed {
			writeError(w, 409, "confirm identity maintenance: reception stops and unfinished transfers are cancelled; completed files and sources are retained")
			return
		}
		c.closeFilesLocked(true)
		_, err := filetransfer.MaintainIdentity(filepath.Join(c.cfg.StateDir, "files-v1"), strings.TrimPrefix(in.Action, "identity_"))
		if err != nil {
			writeError(w, 409, err.Error())
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	f, err := c.ensureFiles()
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	var id string
	if !c.filesLive(f) && (in.Action == "receiving" || in.Action == "send" || in.Action == "resume" || (in.Action == "decide" && in.Accept)) {
		writeError(w, 409, "connect to the mesh first")
		return
	}
	switch in.Action {
	case "receiving":
		err = f.w.Agent.SetReceiving(in.Enabled)
		if err == nil {
			info, e := f.id.Declaration(f.ctrl.Params.NodeKey, 17401, in.Enabled)
			err = e
			if err == nil {
				ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
				err = f.ctrl.PublishFileTransfer(ctx, info)
				cancel()
			}
		}
	case "decide":
		err = f.w.Agent.Decide(in.IDs, in.Accept)
	case "cancel_receive":
		err = f.w.Agent.Cancel(in.ID)
	case "pause_receive", "resume_receive":
		err = f.w.Agent.SetReceivePaused(in.ID, in.Action == "pause_receive")
	case "forget_receive":
		err = f.w.Agent.Forget(in.ID)
	case "send", "resume":
		var ip netip.Addr
		ip, err = netip.ParseAddr(in.Peer)
		if err == nil {
			resume := ""
			if in.Action == "resume" {
				resume = in.ID
			}
			id, err = f.w.Send(ip, in.IDs, resume)
		}
	case "pause":
		err = f.w.Pause(in.ID)
	case "cancel":
		err = f.w.Cancel(in.ID)
	case "forget_job":
		err = f.w.ForgetJob(in.ID)
	case "forget_source":
		err = f.w.ForgetSource(in.ID)
	case "cancel_preparing":
		f.w.CancelPreparation()
	default:
		err = errors.New("unknown file action")
	}
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "id": id})
}

// Detached fd ownership always transfers, including when validation fails.
// Unknown-size/nonseekable sources use bounded streaming disk staging.
func (c *Core) StageFile(fd int32, name string, size int64) (string, error) {
	if fd < 0 {
		return "", errors.New("invalid source descriptor")
	}
	prepareErr := prepareFileFD(fd)
	src := os.NewFile(uintptr(fd), "picked-file")
	defer src.Close()
	if prepareErr != nil {
		return "", prepareErr
	}
	c.fileMu.Lock()
	f, err := c.ensureFiles()
	if err == nil && !c.filesLive(f) {
		err = errors.New("connect to the mesh first")
	}
	c.fileMu.Unlock()
	if err != nil {
		return "", err
	}
	stop := context.AfterFunc(f.w.Context(), func() { _ = src.Close() })
	defer stop()
	s, err := f.w.Stage(f.w.Context(), src, name, size)
	if err != nil {
		return "", err
	}
	return s.ID, nil
}
func (c *Core) SaveFile(id string, fd int32) error {
	if fd < 0 {
		return errors.New("invalid destination descriptor")
	}
	prepareErr := prepareFileFD(fd)
	dst := os.NewFile(uintptr(fd), "picked-destination")
	defer dst.Close()
	if prepareErr != nil {
		return prepareErr
	}
	c.fileMu.Lock()
	f, err := c.ensureFiles()
	c.fileMu.Unlock()
	if err != nil {
		return err
	}
	stop := context.AfterFunc(f.w.Context(), func() { _ = dst.Close() })
	defer stop()
	if err := f.w.Agent.CopyCompleted(f.w.Context(), id, dst); err != nil {
		return err
	}
	return dst.Close()
}
