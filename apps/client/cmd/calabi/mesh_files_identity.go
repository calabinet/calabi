package main

import (
	"errors"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
)

type renewReceptionModes struct {
	scope                           string
	receiving, assisting, clipboard bool
}

func (d *desktopFileAgent) restoreRenewedReception() {
	modes := d.renewRestore
	if modes == nil || d.identity == nil {
		return
	}
	view, err := d.metadata()
	if err != nil {
		return
	}
	if modes.scope != view.Scope+"/"+d.identity.HistoryID() {
		d.renewRestore = nil
		return
	}
	next, err := d.ensure()
	if err != nil {
		return
	}
	for _, mode := range []struct{ assist, clipboard, enabled bool }{
		{false, false, modes.receiving}, {true, false, modes.assisting}, {false, true, modes.clipboard},
	} {
		if mode.enabled {
			if err := d.setInboundMode(next, mode.assist, mode.clipboard, true); err != nil {
				return
			}
		}
	}
	d.renewRestore = nil
}

// Unlike explicit recovery, routine renewal never revokes journals or changes
// the key. Keep receiving modes only in the same authenticated workspace.
func (d *desktopFileAgent) renewIdentityWhenIdle() {
	if !d.opMu.TryLock() {
		return
	}
	defer d.opMu.Unlock()
	d.restoreRenewedReception()
	if d.renewRestore != nil {
		return
	}
	if time.Now().Before(d.renewAfter) || d.identity != nil && !d.identity.RenewalDue() {
		return
	}
	d.wMu.RLock()
	w, scope := d.w, d.scope
	d.wMu.RUnlock()
	var receiving, assisting, clipboard bool
	if w != nil {
		if d.assistActive() || d.shellPasteLive.Load() || !w.RetireForIdentityRenewal() {
			return
		}
		receiving, assisting, clipboard = w.Agent.Receiving(), w.Agent.Assisting(), w.Agent.ClipboardReceiving()
		_ = d.publish(w, false)
		closeErr := w.Close()
		d.wMu.Lock()
		d.w, d.scope = nil, ""
		d.wMu.Unlock()
		if closeErr != nil {
			d.identityError = closeErr
			return
		}
	}
	d.renewAfter = time.Now().Add(time.Hour)
	d.publishMu.Lock()
	id, err := filetransfer.LoadManagedIdentity(d.dir)
	d.identity, d.identityError, d.published = id, err, ""
	d.publishMu.Unlock()
	if err != nil || scope == "" {
		return
	}
	d.renewRestore = &renewReceptionModes{scope: scope, receiving: receiving, assisting: assisting, clipboard: clipboard}
	d.restoreRenewedReception()
}

// Caller holds opMu. publishMu serializes the identity replacement with the
// metadata poller's publication. Close the workspace before taking its identity
// use lock, and never automatically turn reception back on after maintenance.
func (d *desktopFileAgent) maintainIdentity(operation string) error {
	if d.managed != nil {
		d.managed.settings.Receiving = false
		if err := d.saveServiceSettings(); err != nil {
			return err
		}
	}
	d.cancelPreparation()
	d.wMu.RLock()
	w := d.w
	d.wMu.RUnlock()
	if w != nil {
		w.Revoke()
		_ = w.Agent.StopServing()
		_ = d.publish(w, false)
		if err := w.Close(); err != nil {
			return err
		}
		d.wMu.Lock()
		d.w = nil
		d.scope = ""
		d.wMu.Unlock()
	}
	d.publishMu.Lock()
	defer d.publishMu.Unlock()
	id, err := filetransfer.MaintainIdentity(d.dir, operation)
	if err != nil {
		return err
	}
	d.identity = id
	d.identityError = nil
	d.published = ""
	return nil
}

func (d *desktopFileAgent) identitySnapshot() map[string]any {
	status := filetransfer.ReadIdentityStatus(d.dir)
	err := d.identityError
	if err == nil {
		_, err = d.metadata()
	}
	message := ""
	if err != nil {
		message = err.Error()
	}
	if d.identity == nil && message == "" {
		message = errors.New("file identity unavailable").Error()
	}
	return map[string]any{"available": false, "receiving": false, "preparing": false, "peers": []any{}, "received": []any{}, "jobs": []any{}, "sources": []any{}, "identity": status, "unavailable_reason": message}
}
