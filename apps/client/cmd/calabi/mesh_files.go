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
	"github.com/calabinet/calabi/apps/client/internal/filecontrol"
	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
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
	"syscall"
	"time"
)

type desktopFileAgent struct {
	closeOnce       sync.Once
	console         string
	ctx             context.Context
	cancel          context.CancelFunc
	dir             string
	identity        *filetransfer.Identity
	identityError   error
	lease           string
	mu              sync.RWMutex // live metadata only, never held during disk IO or HTTP
	view            filecontrol.Snapshot
	updated         time.Time
	metaError       string
	opMu            sync.Mutex // main/stdin owns UI actions; poll loop only snapshots workspace pointer
	w               *filetransfer.Workspace
	scope           string
	wMu             sync.RWMutex
	publishMu       sync.Mutex
	published       string
	stageMu         sync.Mutex
	stageCancel     context.CancelFunc
	stageGeneration uint64
	stageError      string
}
type fileAction struct {
	Owner     uint64   `json:"owner,omitempty"`
	Action    string   `json:"action"`
	Peer      string   `json:"peer"`
	ID        string   `json:"id"`
	IDs       []string `json:"ids"`
	Enabled   bool     `json:"enabled"`
	Accept    bool     `json:"accept"`
	Confirmed bool     `json:"confirmed"`
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
	id, identityErr := filetransfer.LoadIdentity(dir)
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
	context.AfterFunc(agentCtx, d.close)
	go d.loop()
	return d, nil
}
func (d *desktopFileAgent) poll() {
	view, err := filecontrol.Call(d.ctx, d.console, filecontrol.Request{Op: "snapshot", Lease: d.lease})
	d.mu.Lock()
	d.updated = time.Now()
	if err != nil {
		d.view = filecontrol.Snapshot{}
		d.metaError = err.Error()
	} else {
		d.view = view
		d.metaError = ""
	}
	d.mu.Unlock()
	if err == nil && view.Ready {
		d.wMu.RLock()
		w := d.w
		d.wMu.RUnlock()
		if w != nil {
			if (w.Agent.Receiving() || w.NeedsControlSession()) && !view.OwnsLease {
				if err := d.publish(w, true); err != nil && strings.Contains(err.Error(), "another local user session") && w.Agent.Receiving() {
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
			d.poll()
			n++
			if n%20 == 0 {
				d.wMu.RLock()
				w := d.w
				d.wMu.RUnlock()
				if w != nil {
					active := w.Agent.Receiving() || w.NeedsControlSession()
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
	w, oldScope := d.w, d.scope
	d.wMu.RUnlock()
	if w != nil && oldScope == scope && w.Agent.Alive() {
		return w, nil
	}
	if w != nil {
		d.cancelPreparation()
		if oldScope != scope {
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
	resolve := func(ip netip.Addr) (filetransfer.Grant, bool) {
		v, err := d.metadata()
		if err != nil || v.Scope != view.Scope {
			return filetransfer.Grant{}, false
		}
		for _, p := range v.Peers {
			if p.Grant.Peer.IP == ip && time.Now().Unix() < p.ExpiresUnix {
				return p.Grant, true
			}
		}
		return filetransfer.Grant{}, false
	}
	incoming := func(ip netip.Addr, port uint16) bool {
		v, err := d.metadata()
		if err != nil || v.Scope != view.Scope || port != 17401 {
			return false
		}
		for _, p := range v.Peers {
			if p.Grant.Peer.IP == ip && time.Now().Unix() < p.ExpiresUnix {
				return p.Incoming
			}
		}
		return false
	}
	authority := func() bool { v, err := d.metadata(); return err == nil && v.Scope == view.Scope && v.OwnsLease }
	w, err = filetransfer.NewWorkspace(filetransfer.AgentConfig{Authority: authority, Identity: d.identity, Directory: dir, Scope: scope, LocalIP: local, Port: 17401, Kbps: filetransfer.DefaultDeviceKbps, MaxBytes: 8 << 30, Resolve: resolve, Incoming: incoming})
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
	d.wMu.Unlock()
	return w, nil
}
func (d *desktopFileAgent) publish(w *filetransfer.Workspace, active bool) error {
	d.publishMu.Lock()
	defer d.publishMu.Unlock()
	view, err := d.metadata()
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
	if active {
		key, err := meshproto.ParseNodeKey(view.NodeKey)
		if err != nil {
			return err
		}
		req.Info, err = d.identity.Declaration(key, 17401, w.Agent.Receiving())
		if err != nil {
			return err
		}
	} else if d.published != view.Scope {
		return nil
	}
	callCtx := d.ctx
	if !active {
		var cancel context.CancelFunc
		callCtx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
	}
	updated, callErr := filecontrol.Call(callCtx, d.console, req)
	err = callErr
	if err == nil {
		d.mu.Lock()
		d.view = updated
		d.updated = time.Now()
		d.mu.Unlock()
		if active {
			d.published = view.Scope
		} else {
			d.published = ""
		}
	}
	return err
}
func (d *desktopFileAgent) handle(a fileAction) (any, error) {
	d.opMu.Lock()
	defer d.opMu.Unlock()
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
		d.cancelPreparation()
		d.wMu.RLock()
		current := d.w
		d.wMu.RUnlock()
		if current != nil {
			_ = current.Agent.SetReceiving(false)
			current.Revoke()
			_ = d.publish(current, false)
		}
		return map[string]bool{"ok": true}, nil
	}
	w, err := d.ensure()
	if err != nil {
		if a.Action == "snapshot" {
			state := d.identitySnapshot()
			state["unavailable_reason"] = err.Error()
			return state, nil
		}
		return nil, err
	}
	result := func() map[string]any {
		v, _ := d.metadata()
		d.stageMu.Lock()
		preparing, preparationError := d.stageCancel != nil, d.stageError
		d.stageMu.Unlock()
		return map[string]any{"available": true, "preparing": preparing, "preparation_error": preparationError, "receiving": w.Agent.Receiving(), "peers": v.Peers, "received": w.Agent.List(), "jobs": w.Jobs(), "sources": w.Staged(), "identity": filetransfer.ReadIdentityStatus(d.dir)}
	}
	switch a.Action {
	case "snapshot":
		return result(), nil
	case "receiving":
		err = d.setReceiving(w, a.Enabled)
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
	case "revoke":
		err = w.Agent.SetReceiving(false)
		w.Revoke()
		_ = d.publish(w, false)
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
			err = saveVerifiedFile(w, a.ID, path)
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
		d.cancelPreparation()
		d.wMu.RLock()
		w := d.w
		d.wMu.RUnlock()
		if w != nil {
			// Process exit checkpoints durable tasks. Explicit logout, identity
			// maintenance and scope changes use Revoke separately.
			_ = w.Close()
			_ = d.publish(w, false)
		}
		d.cancel()
	})
}

func (d *desktopFileAgent) setReceiving(w *filetransfer.Workspace, enabled bool) error {
	if !enabled {
		err := w.Agent.StopServing()
		active := w.NeedsControlSession()
		for _, j := range w.Jobs() {
			active = active || j.State == "sending"
		}
		return errors.Join(err, d.publish(w, active))
	}
	if w.Agent.Receiving() {
		return d.publish(w, true)
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
	if err := w.Agent.SetReceiving(true); err != nil {
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

// stdio is a private parent-child pipe, not a machine HTTP endpoint. Only
// allowlisted actions cross it; native dialogs choose all source/destination
// paths within this ordinary user's process.
func runMeshFiles(args []string) int {
	fs := flag.NewFlagSet("mesh files", flag.ContinueOnError)
	stdio := fs.Bool("stdio", false, "private JSON-lines protocol for desktop shell")
	console := fs.String("console", "http://127.0.0.1:7400", "exact supervised daemon console URL")
	web := fs.String("web", "", "Linux browser control: explicit loopback or this device's overlay IP:port")
	webDir := fs.String("web-dir", "", "existing directory for browser file selection and export")
	if fs.Parse(args) != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: calabi mesh files [--stdio | --web IP:port --web-dir directory] [--console http://127.0.0.1:7400]")
		return 2
	}
	if (*web != "" && (runtime.GOOS != "linux" || *stdio || *webDir == "")) || (*web == "" && *webDir != "") {
		fmt.Fprintln(os.Stderr, "browser control requires Linux, --web IP:port and --web-dir; it cannot be combined with --stdio")
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
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
		return d.consoleLoop()
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 8192), 16<<10)
	writer := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var action fileAction
		dec := json.NewDecoder(strings.NewReader(scanner.Text()))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&action); err != nil {
			_ = writer.Encode(map[string]any{"error": "invalid file action"})
			continue
		}
		result, err := d.handle(action)
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

func (d *desktopFileAgent) consoleLoop() int {
	fmt.Println("File transfers (current OS user). Reception starts off.\nCommands: list | receive on/off | stage <local-path> | export <file-ID> <new-local-path> | pick | send <peer-IP> <source-ID...> | accept/reject <file-ID...> | save <file-ID> | pause/resume/cancel <job-ID> | pause_receive/resume_receive/cancel_receive/forget_receive/forget_job/forget_source <ID> | identity status/renew/reset | quit")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 16<<10)
	stop := context.AfterFunc(d.ctx, func() { _ = os.Stdin.Close() })
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
			if err := d.stageLocal(path); err != nil {
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
			if err := d.exportLocal(args[1], path); err != nil {
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
		out, err := d.handle(a)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		body, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(body))
	}
	return 0
}
