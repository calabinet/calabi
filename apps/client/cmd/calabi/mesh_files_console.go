package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
)

// Terminal actions accept paths only from the local OS user, including over
// the Windows user pipe. The desktop UI cannot request these actions.
func (d *desktopFileAgent) handleConsoleAction(action fileAction) (any, error) {
	switch action.Action {
	case "console_stage", "console_export":
		if len(action.Paths) != 1 || action.Paths[0] == "" {
			return nil, errors.New("one local file path required")
		}
		if action.Action == "console_stage" {
			return nil, d.stageLocal(action.Paths[0])
		}
		return nil, d.exportLocal(action.ID, action.Paths[0])
	default:
		return d.handle(action)
	}
}

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
