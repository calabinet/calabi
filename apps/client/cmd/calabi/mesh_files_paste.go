package main

import (
	"runtime"
	"slices"

	"github.com/calabinet/calabi/apps/client/internal/filecontrol"
	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
)

func permitsRDPCopy(m filecontrol.Member, host bool, port uint16) (allowed, bind bool) {
	if !host && m.OS != "windows" && !m.OwnWindows {
		return false, false
	}
	if m.SameOwner || m.OwnWindows {
		return true, false
	}
	if port == 0 {
		return false, false
	}
	ports := m.RemoteLoginPorts
	if host {
		ports = m.IncomingRemoteLoginPorts
	}
	if m.RDPAccessAllowed || slices.Contains(ports, port) {
		return true, true
	}
	return false, false
}

func (d *desktopFileAgent) meshCopyPeer(g filetransfer.Grant, host bool, port uint16) (bool, bool) {
	if !d.shellPasteLive.Load() || host && runtime.GOOS != "windows" {
		return false, false
	}
	v, err := d.metadata()
	if err != nil || !v.Ready {
		return false, false
	}
	for _, m := range v.Members {
		if m.DeviceKey == g.DeviceKey && m.IP == g.Peer.IP.String() && m.IP != v.Overlay {
			return permitsRDPCopy(m, host, port)
		}
	}
	return false, false
}

func (d *desktopFileAgent) clipboardPeer(g filetransfer.Grant) bool {
	if !d.shellPasteLive.Load() {
		return false
	}
	v, e := d.metadata()
	if e != nil || !v.Ready {
		return false
	}
	for _, m := range v.Members {
		if (m.SameOwner || m.OwnWindows) && m.DeviceKey == g.DeviceKey && m.IP == g.Peer.IP.String() && m.IP != v.Overlay {
			return true
		}
	}
	return false
}
func (d *desktopFileAgent) reconcileClipboard() {
	if !d.shellPasteLive.Load() {
		d.opMu.Lock()
		defer d.opMu.Unlock()
		d.wMu.RLock()
		w := d.w
		d.wMu.RUnlock()
		if w != nil && w.Agent.ClipboardReceiving() {
			_ = d.setInboundMode(w, false, true, false)
		}
		return
	}
	d.opMu.Lock()
	defer d.opMu.Unlock()
	w, e := d.ensure()
	if e != nil || w.Agent.ClipboardReceiving() {
		return
	}
	_ = d.setInboundMode(w, false, true, true)
}
