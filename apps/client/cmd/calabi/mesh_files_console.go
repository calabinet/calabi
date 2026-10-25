package main

import (
	"errors"
	"os"

	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
)

// Terminal actions accept paths from the invoking user. Native save uses the
// same exclusive writer after the OS chooser. No arbitrary path is accepted
// by the stdio UI API, metadata IPC, or the privileged mesh daemon.
func (d *desktopFileAgent) stageLocal(path string) error {
	d.opMu.Lock()
	defer d.opMu.Unlock()
	w, err := d.ensure()
	if err != nil {
		return err
	}
	d.stageMu.Lock()
	preparing := d.stageCancel != nil
	d.stageMu.Unlock()
	if preparing {
		return errors.New("another file preparation is active")
	}
	d.startPreparation(w, []string{path})
	return nil
}

func (d *desktopFileAgent) exportLocal(id, path string) (err error) {
	d.opMu.Lock()
	defer d.opMu.Unlock()
	w, err := d.ensure()
	if err != nil {
		return err
	}
	return saveVerifiedFile(w, id, path)
}

func saveVerifiedFile(w *filetransfer.Workspace, id, path string) (err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(path)
		}
	}()
	err = w.Agent.CopyCompleted(w.Context(), id, f)
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}
