package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Only the private desktop stdin API calls this. Scope/owned-device checks
// are repeated here rather than trusting a device row cached by the frontend.
func (d *desktopFileAgent) rdpCopyAction(w *filetransfer.Workspace, a fileAction) (any, error) {
	v, err := d.metadata()
	if err != nil || !v.Ready {
		return nil, errors.New("mesh metadata unavailable")
	}
	ip := netip.Addr{}
	for _, m := range v.Members {
		if m.OwnWindows && m.DeviceKey == a.Peer {
			ip, _ = netip.ParseAddr(m.IP)
		}
	}
	if !ip.IsValid() || ip.String() == v.Overlay {
		return nil, errors.New("owned Windows target required")
	}
	if a.Action == "rdp_copy_status" {
		for _, j := range w.Jobs() {
			if j.ID == a.ID && j.PeerIP == ip.String() {
				if j.State == "failed" || j.State == "cancelled" {
					return nil, errors.New("file offer stopped")
				}
				if filetransfer.ShellOfferReady(j.Progress) {
					return map[string]string{"token": v.NodeKey + "/" + j.Progress.Batch}, nil
				}
				return map[string]string{"pending": "true"}, nil
			}
		}
		return nil, errors.New("clipboard job unavailable")
	}
	if len(a.Paths) < 1 || len(a.Paths) > 32 {
		return nil, errors.New("select 1..32 files")
	}
	// Validate the whole selection before recording a source. This path is only
	// enabled by the explicit file-copy checkbox in an active RDP helper.
	var total int64
	for _, path := range a.Paths {
		st, e := os.Lstat(path)
		if !filepath.IsAbs(path) || e != nil || !st.Mode().IsRegular() || st.Size() > filetransfer.ShellPasteLimit-total {
			return nil, errors.New("clipboard files must be ordinary files totaling at most 100 MiB")
		}
		total += st.Size()
	}
	var ids []string
	cleanup := func() {
		for _, id := range ids {
			_ = w.ForgetSource(id)
		}
	}
	for _, path := range a.Paths {
		s, e := w.ReferenceLocal(d.ctx, path)
		if e != nil {
			cleanup()
			return nil, e
		}
		ids = append(ids, s.ID)
	}
	if err := d.publish(w, true); err != nil {
		cleanup()
		return nil, err
	}
	id, err := w.SendClipboard(ip, ids)
	if err != nil {
		cleanup()
		return nil, err
	}
	return map[string]string{"job": id}, nil
}

// The receiver helper is a child of the ordinary user's agent, so its OLE
// clipboard and progress window belong to that exact Windows logon session.
// No SYSTEM process injects a UI into a different user/session.
func (d *desktopFileAgent) startShellPaste() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	helper := filepath.Join(filepath.Dir(exe), "rdp", "calabi-paste.exe")
	if st, err := os.Stat(helper); err != nil || !st.Mode().IsRegular() {
		return
	}
	cmd := exec.CommandContext(d.ctx, helper, "--bridge")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
	input, err := cmd.StdinPipe()
	if err != nil {
		return
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		input.Close()
		return
	}
	cmd.Stderr = &pasteUILog{agent: d}
	if err = cmd.Start(); err != nil {
		input.Close()
		output.Close()
		return
	}
	d.shellPasteLive.Store(true)
	d.background.Add(1)
	go func() {
		defer d.background.Done()
		defer d.shellPasteLive.Store(false)
		defer input.Close()
		defer output.Close()
		defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
		var paste *filetransfer.ShellPaste
		var marker, scope string
		defer func() {
			d.opMu.Lock()
			defer d.opMu.Unlock()
			d.shellPasteMarker = ""
			if paste != nil {
				paste.Close()
			}
		}()
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 4096), 20000)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			reply := "error"
			if len(fields) > 0 && strings.HasPrefix(fields[0], "mesh_") {
				reply = d.meshPasteRequest(fields, "")
			} else if len(fields) >= 2 && len(fields[1]) <= 256 {
				func() {
					d.opMu.Lock()
					defer d.opMu.Unlock()
					if fields[0] == "cancel" || fields[0] == "release" {
						if paste != nil && marker == fields[1] {
							paste.Close()
							paste = nil
							marker = ""
							d.shellPasteMarker = ""
							reply = "ok"
						}
						return
					}
					w, err := d.ensure()
					if err != nil {
						return
					}
					v, err := d.metadata()
					if err != nil || !v.Ready || !w.Agent.ClipboardReceiving() {
						return
					}
					split := strings.LastIndex(fields[1], "/")
					if split <= 0 {
						return
					}
					device, batch := fields[1][:split], fields[1][split+1:]
					owned := false
					for _, m := range v.Members {
						if m.OwnWindows && m.DeviceKey == device && m.IP != v.Overlay {
							owned = true
						}
					}
					if !owned {
						return
					}
					if fields[0] == "resolve" {
						d.shellPasteMarker = ""
						if paste != nil {
							paste.Close()
							paste = nil
						}
						paste, err = w.Agent.NewShellPaste(d.ctx, d.dir, device, batch)
						if err != nil {
							return
						}
						marker, scope = fields[1], v.Scope
						d.shellPasteMarker = marker
						reply = "data " + hex.EncodeToString(paste.Manifest())
						return
					}
					if paste == nil || marker != fields[1] || scope != v.Scope {
						return
					}
					switch fields[0] {
					case "begin":
						if paste.Begin() == nil {
							reply = "ok"
						}
					case "status":
						if len(fields) != 3 {
							return
						}
						index, e := strconv.Atoi(fields[2])
						if e != nil {
							return
						}
						ready, done, total, e := paste.Status(index)
						if e != nil {
							return
						}
						state := "wait"
						if ready {
							state = "ready"
						}
						reply = fmt.Sprintf("%s %d %d", state, done, total)
					case "read":
						if len(fields) != 5 {
							return
						}
						index, e1 := strconv.Atoi(fields[2])
						offset, e2 := strconv.ParseInt(fields[3], 10, 64)
						count, e3 := strconv.Atoi(fields[4])
						if e1 != nil || e2 != nil || e3 != nil {
							return
						}
						data, e := paste.Read(index, offset, count)
						if e == nil {
							reply = "data " + hex.EncodeToString(data)
						}
					}
				}()
			}
			if _, err := fmt.Fprintln(input, reply); err != nil {
				break
			}
		}
	}()
}

// Private child diagnostics: bounded window state only, no paths or file content.
type pasteUILog struct {
	agent   *desktopFileAgent
	pending string
}

func (l *pasteUILog) Write(p []byte) (int, error) {
	l.pending += string(p)
	for {
		line, tail, ok := strings.Cut(l.pending, "\n")
		if !ok {
			break
		}
		l.pending = tail
		line = strings.TrimSpace(line)
		stream := strings.HasPrefix(line, "rdp_stream ")
		if len(line) > 512 || (!strings.HasPrefix(line, "paste_ui ") && !stream) {
			continue
		}
		level := "WARN"
		if strings.Contains(line, "visible=1 topmost=1 show_ok=1") {
			level = "INFO"
		}
		action, detail := "rdp_paste_ui", strings.TrimPrefix(line, "paste_ui ")
		if stream {
			action, detail = "rdp_paste_stream", strings.TrimPrefix(line, "rdp_stream ")
			if strings.Contains(line, "hr=0x00000000") && !strings.HasSuffix(line, "received=0") {
				level = "INFO"
			}
		}
		l.agent.mu.RLock()
		ip, _ := netip.ParseAddr(l.agent.view.Overlay)
		l.agent.mu.RUnlock()
		l.agent.recordPeerEvent(ip, detail, action, level)
	}
	if len(l.pending) > 512 {
		l.pending = ""
	}
	return len(p), nil
}
