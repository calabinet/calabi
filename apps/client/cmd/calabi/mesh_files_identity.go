package main

import (
	"errors"

	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
)

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
