package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

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
	return writeVerifiedDestination(path, false, func(dst io.Writer) error {
		return w.Agent.CopyCompleted(w.Context(), id, dst)
	})
}

// Native save panels confirm replacement. Console and managed exports retain
// exclusive creation; only this native-dialog action may replace a destination.
func saveVerifiedFileReplacing(w *filetransfer.Workspace, id, path string) error {
	return writeVerifiedDestination(path, true, func(dst io.Writer) error {
		return w.Agent.CopyCompleted(w.Context(), id, dst)
	})
}

func writeVerifiedDestination(path string, replace bool, copyVerified func(io.Writer) error) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("cannot save received file: %w", err)
		}
	}()
	var f *os.File
	if replace {
		f, err = os.CreateTemp(filepath.Dir(path), ".calabi-save-*")
	} else {
		f, err = os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	}
	if err != nil {
		return err
	}
	created := f.Name()
	committed := false
	defer func() {
		if !committed {
			_ = f.Close()
			_ = os.Remove(created)
		}
	}()
	err = copyVerified(f)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if replace {
		if err = os.Rename(created, path); err != nil {
			return err
		}
	}
	committed = true
	return nil
}
