package main

import (
	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
)

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
