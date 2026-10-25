package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
)

type mobileFileTest struct {
	identity  *filetransfer.Identity
	r         *filetransfer.Receiver
	server    *http.Server
	sender    *filetransfer.Sender
	dir       string
	cancel    context.CancelFunc
	allowed   atomic.Bool
	mu        sync.Mutex
	sending   bool
	progress  filetransfer.Transfer
	lastError string
	running   bool // c.fileMu
}

func (c *Core) ensureFileTest() (*mobileFileTest, error) {
	if !c.cfg.FileTransferP0 {
		return nil, errors.New("file transfer P0 is disabled")
	}
	if c.fileTest == nil {
		identity, err := filetransfer.NewIdentity()
		if err != nil {
			return nil, err
		}
		c.fileTest = &mobileFileTest{identity: identity}
	}
	return c.fileTest, nil
}

func (c *Core) handleFileTest(w http.ResponseWriter, _ *http.Request) {
	c.fileMu.Lock()
	defer c.fileMu.Unlock()
	f, err := c.ensureFileTest()
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	f.mu.Lock()
	sending, progress, lastError := f.sending, f.progress, f.lastError
	f.mu.Unlock()
	transfers := []filetransfer.Transfer{}
	if f.r != nil {
		transfers = f.r.List()
	}
	writeJSON(w, 200, map[string]any{"fingerprint": f.identity.Fingerprint, "running": f.running && f.allowed.Load(), "sending": sending, "outgoing": progress, "error": lastError, "transfers": transfers})
}

func (c *Core) handleFileTestStart(w http.ResponseWriter, req *http.Request) {
	var in struct {
		PeerIP      string `json:"peer_ip"`
		Fingerprint string `json:"fingerprint"`
		Port        int    `json:"port"`
		Kbps        int    `json:"kbps"`
	}
	if err := json.NewDecoder(io.LimitReader(req.Body, 4096)).Decode(&in); err != nil {
		writeError(w, 400, "invalid filetest settings")
		return
	}
	if in.Port == 0 {
		in.Port = 17401
	}
	if in.Kbps == 0 {
		in.Kbps = filetransfer.DefaultKbps
	}
	ip, err := netip.ParseAddr(in.PeerIP)
	if err != nil {
		writeError(w, 400, "exact peer mesh IP required")
		return
	}
	peer := filetransfer.Peer{IP: ip, Fingerprint: strings.TrimSpace(in.Fingerprint)}
	if err := peer.Validate(); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	e := c.currentEngine()
	if e == nil {
		writeError(w, 409, "connect to the mesh first")
		return
	}
	st := e.status()
	local, err := netip.ParseAddr(st.Overlay)
	if err != nil || st.State != stateConnected {
		writeError(w, 409, "mesh has no connected address")
		return
	}
	e.mu.Lock()
	ctrl := e.ctrl
	e.mu.Unlock()
	key := ctrl.DeviceKeyForIP(ip)
	if key == "" {
		writeError(w, 409, "peer is not an exact device address in the mesh map")
		return
	}
	pacer, err := filetransfer.NewPacer(in.Kbps)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	addr, err := filetransfer.Address(local, in.Port)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	c.fileMu.Lock()
	defer c.fileMu.Unlock()
	f, err := c.ensureFileTest()
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if f.r != nil {
		writeError(w, 409, "save received files, then clear the previous experiment before starting another")
		return
	}
	c.closeFilesLocked(true)
	allowed := func() bool {
		if !f.allowed.Load() || c.currentEngine() != e {
			return false
		}
		next := e.status()
		e.mu.Lock()
		currentCtrl := e.ctrl
		e.mu.Unlock()
		if next.State != stateConnected || next.Overlay != local.String() || currentCtrl != ctrl || currentCtrl.DeviceKeyForIP(ip) != key {
			return false
		}
		e.mu.Lock()
		dp, blocked := e.dp, e.settings.BlockIncoming
		e.mu.Unlock()
		return !blocked && dp.IncomingTCPAllowed(ip, uint16(in.Port))
	}
	f.allowed.Store(true)
	if !allowed() {
		f.allowed.Store(false)
		writeError(w, 403, "current inbound policy blocks filetest")
		return
	}
	dir, err := os.MkdirTemp(c.cfg.StateDir, "filetest-p0-")
	if err != nil {
		f.allowed.Store(false)
		writeError(w, 500, "cannot create private inbox")
		return
	}
	receiver, err := filetransfer.NewReceiver(filetransfer.ReceiverConfig{Peer: peer, Directory: dir, Kbps: in.Kbps, MaxBytes: 8 << 30, Budget: pacer, Allowed: allowed})
	if err != nil {
		f.allowed.Store(false)
		_ = os.Remove(dir)
		writeError(w, 500, err.Error())
		return
	}
	sender, err := filetransfer.NewSender(f.identity, local, peer, in.Port, pacer, allowed)
	if err != nil {
		f.allowed.Store(false)
		_ = receiver.Close()
		_ = os.Remove(dir)
		writeError(w, 500, err.Error())
		return
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		f.allowed.Store(false)
		sender.Close()
		_ = receiver.Close()
		_ = os.Remove(dir)
		writeError(w, 500, "cannot listen on the mesh address: "+err.Error())
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	f.r, f.sender, f.dir, f.cancel, f.running = receiver, sender, dir, cancel, true
	server, done := receiver.Serve(listener, f.identity)
	f.server = server
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		defer func() { f.allowed.Store(false); cancel(); _ = server.Close(); receiver.Stop() }()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-ticker.C:
				if !allowed() {
					return
				}
			}
		}
	}()
	writeJSON(w, 200, map[string]any{"running": true, "overlay": local.String(), "port": in.Port})
}

func (c *Core) handleFileTestDecide(w http.ResponseWriter, req *http.Request) {
	var in struct {
		ID     string `json:"id"`
		Accept bool   `json:"accept"`
		Cancel bool   `json:"cancel"`
	}
	if err := json.NewDecoder(io.LimitReader(req.Body, 4096)).Decode(&in); err != nil {
		writeError(w, 400, "invalid decision")
		return
	}
	c.fileMu.Lock()
	defer c.fileMu.Unlock()
	if c.fileTest == nil || c.fileTest.r == nil {
		writeError(w, 409, "filetest is not running")
		return
	}
	var err error
	if in.Cancel {
		err = c.fileTest.r.Cancel(in.ID)
	} else {
		err = c.fileTest.r.Decide(in.ID, in.Accept)
	}
	if err != nil {
		writeError(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (c *Core) stopFileTest() {
	c.fileMu.Lock()
	defer c.fileMu.Unlock()
	c.stopFileTestLocked()
}

func (c *Core) stopFileTestLocked() {
	if f := c.fileTest; f != nil {
		f.allowed.Store(false)
		f.running = false
		if f.cancel != nil {
			f.cancel()
		}
		if f.server != nil {
			_ = f.server.Close()
		}
		if f.r != nil {
			f.r.Stop()
		}
		if f.sender != nil {
			f.sender.Close()
		}
	}
}

func (c *Core) handleFileTestStop(w http.ResponseWriter, _ *http.Request) {
	c.stopFileTest()
	writeJSON(w, 200, map[string]bool{"stopped": true})
}

func (c *Core) handleFileTestClear(w http.ResponseWriter, _ *http.Request) {
	c.stopFileTest()
	c.fileMu.Lock()
	defer c.fileMu.Unlock()
	if f := c.fileTest; f != nil {
		f.mu.Lock()
		sending := f.sending
		f.mu.Unlock()
		if sending {
			writeError(w, 409, "wait for the outgoing file to stop before clearing")
			return
		}
		if f.r != nil {
			_ = f.r.Close()
		}
		// The directory was created locally by MkdirTemp. Only delete its direct
		// regular entries: no recursive traversal, user path or remote filename.
	}
	if err := clearFileTestInboxes(c.cfg.StateDir); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	c.fileTest = nil
	writeJSON(w, 200, map[string]bool{"cleared": true})
}

// SendFileTest takes ownership of a SAF descriptor detached by Android. Bytes
// never cross JSON/JNI; non-seekable or unknown-sized providers fail explicitly.
func (c *Core) SendFileTest(fd int32, name string, size int64) error {
	if fd < 0 {
		return errors.New("invalid file descriptor")
	}
	file := os.NewFile(uintptr(fd), "selected-document")
	if file == nil {
		return errors.New("invalid file descriptor")
	}
	c.fileMu.Lock()
	f := c.fileTest
	if !c.cfg.FileTransferP0 || f == nil || !f.running || !f.allowed.Load() {
		c.fileMu.Unlock()
		_ = file.Close()
		return errors.New("filetest is not running")
	}
	f.mu.Lock()
	if f.sending {
		f.mu.Unlock()
		c.fileMu.Unlock()
		_ = file.Close()
		return errors.New("another file send is active")
	}
	f.sending, f.lastError = true, ""
	f.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 24*time.Hour)
	// Stop/revocation also interrupts hashing, before the first network request.
	c.fileMu.Unlock()
	go func() {
		defer file.Close()
		defer cancel()
		stopRead := context.AfterFunc(ctx, func() { _ = file.Close() })
		defer stopRead()
		watchDone := make(chan struct{})
		go func() {
			defer close(watchDone)
			ticker := time.NewTicker(250 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if !f.allowed.Load() {
						cancel()
						return
					}
				}
			}
		}()
		result, err := f.sender.Send(ctx, file, name, size, func(p filetransfer.Transfer) { f.mu.Lock(); f.progress = p; f.mu.Unlock() })
		cancel()
		<-watchDone
		f.mu.Lock()
		f.sending = false
		f.progress = result
		if err != nil {
			f.lastError = err.Error()
		}
		f.mu.Unlock()
	}()
	return nil
}

// SaveFileTest exports a verified inbox ID to a caller-owned SAF output fd.
// It closes the descriptor on every path and reports provider write failures.
func (c *Core) SaveFileTest(id string, fd int32) error {
	if fd < 0 {
		return errors.New("invalid output descriptor")
	}
	file := os.NewFile(uintptr(fd), "destination-document")
	if file == nil {
		return errors.New("invalid output descriptor")
	}
	defer file.Close()
	c.fileMu.Lock()
	if !c.cfg.FileTransferP0 || c.fileTest == nil || c.fileTest.r == nil {
		c.fileMu.Unlock()
		return errors.New("no test inbox")
	}
	receiver := c.fileTest.r
	c.fileMu.Unlock()
	if err := receiver.CopyCompleted(context.Background(), id, file); err != nil {
		return err
	}
	// Explicit close surfaces a provider error before reporting saved. Some
	// document providers do not support fsync; no rename/fsync promise is made.
	if err := file.Close(); err != nil {
		return fmt.Errorf("saving document: %w", err)
	}
	return nil
}

// Explicit local clear also removes caches left by a process restart. Only
// the private experiment prefix and known random file names are eligible.
func clearFileTestInboxes(stateDir string) error {
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.HasPrefix(entry.Name(), "filetest-p0-") {
			continue
		}
		dir := filepath.Join(stateDir, entry.Name())
		root, err := os.OpenRoot(dir)
		if err != nil {
			return err
		}
		err = func() error {
			defer root.Close()
			folder, err := root.Open(".")
			if err != nil {
				return err
			}
			files, err := folder.ReadDir(-1)
			_ = folder.Close()
			if err != nil {
				return err
			}
			for _, file := range files {
				name := file.Name()
				stem := strings.TrimSuffix(strings.TrimSuffix(name, ".part"), ".received")
				if !file.Type().IsRegular() || len(stem) != 64 || (name != stem+".part" && name != stem+".received") {
					return errors.New("unexpected P0 inbox entry; refusing to clear")
				}
				for _, c := range stem {
					if !strings.ContainsRune("0123456789abcdef", c) {
						return errors.New("unexpected P0 inbox filename")
					}
				}
			}
			for _, file := range files {
				if err := root.Remove(file.Name()); err != nil {
					return err
				}
			}
			return nil
		}()
		if err != nil {
			return err
		}
		if err := os.Remove(dir); err != nil {
			return err
		}
	}
	return nil
}
