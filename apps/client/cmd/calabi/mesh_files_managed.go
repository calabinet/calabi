package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/filetransfer"
)

// Linux's managed service and ordinary Windows/macOS agents persist reception.
// Preferences are private to the OS user, identity and authenticated scope.
type fileServiceSettings struct {
	Scope     string            `json:"scope"`
	Epoch     int64             `json:"epoch"`
	Receiving bool              `json:"receiving"`
	AutoSave  bool              `json:"auto_save"`
	Saved     map[string]string `json:"saved,omitempty"`
	Exported  map[string]bool   `json:"exported,omitempty"`
}
type fileServiceState struct {
	saving    bool
	saveError string
	saveAfter time.Time
	dirty     bool
	settings  fileServiceSettings
	directory string
	err       string
}

func (d *desktopFileAgent) saveServiceSettings() (retErr error) {
	defer func() { d.managed.dirty = retErr != nil }()
	root, err := os.OpenRoot(d.dir)
	if err != nil {
		return err
	}
	defer root.Close()
	body, err := json.Marshal(d.managed.settings)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(d.dir, "receive-settings-*.tmp")
	if err != nil {
		return err
	}
	name := filepath.Base(f.Name())
	defer root.Remove(name)
	_, err = f.Write(body)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	return root.Rename(name, "receive-settings.json")
}

func (d *desktopFileAgent) configureManaged(directory string) error {
	d.opMu.Lock()
	defer d.opMu.Unlock()
	if view, err := d.metadata(); err == nil && view.OwnsLease {
		// A crash/offline shutdown may leave our own short-lived declaration.
		// The workspace's OS lock, rather than that lease alone, distinguishes
		// recovery from a second live process using the same private profile.
		if _, err := d.ensure(); err != nil {
			return fmt.Errorf("cannot attach file profile; stop any old file process first: %w", err)
		}
	}
	m := &fileServiceState{directory: directory}
	b, err := os.ReadFile(filepath.Join(d.dir, "receive-settings.json"))
	if err == nil {
		if err := json.Unmarshal(b, &m.settings); err != nil {
			return fmt.Errorf("invalid saved reception settings: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if m.settings.Saved == nil {
		m.settings.Saved = map[string]string{}
	}
	if m.settings.Exported == nil {
		m.settings.Exported = map[string]bool{}
	}
	d.managed = m
	return nil
}

func (d *desktopFileAgent) managedSnapshot() map[string]any {
	if d.managed == nil {
		return nil
	}
	saved := map[string]string{}
	for id, name := range d.managed.settings.Saved {
		if d.managed.settings.Exported[id] {
			saved[id] = name
		}
	}
	return map[string]any{"persistent": true, "managed": d.managed.directory != "", "directory": d.managed.directory, "receiving_requested": d.managed.settings.Receiving, "auto_save": d.managed.settings.AutoSave, "error": func() string {
		if d.managed.err != "" {
			return d.managed.err
		}
		return d.managed.saveError
	}(), "saved": saved}
}

func (d *desktopFileAgent) reconcileManaged() {
	// Native dialogs and verified exports can hold the UI lock for minutes.
	// Reconciliation may wait for the next tick; metadata and lease polling may not.
	if !d.opMu.TryLock() {
		return
	}
	defer d.opMu.Unlock()
	if d.managed == nil {
		return
	}
	m := d.managed
	previousError := m.err
	defer func() {
		if m.err != previousError && m.err != "" {
			fmt.Fprintln(os.Stderr, "File service:", m.err)
		}
	}()
	if m.dirty {
		if err := d.saveServiceSettings(); err != nil {
			m.err = err.Error()
			d.wMu.RLock()
			w := d.w
			d.wMu.RUnlock()
			if w != nil {
				_ = w.Agent.StopServing()
			}
			return
		}
	}
	view, err := d.metadata()
	if err != nil {
		d.wMu.RLock()
		w := d.w
		d.wMu.RUnlock()
		if w != nil && w.Agent.Receiving() {
			_ = w.Agent.StopServing()
		}
		m.err = err.Error()
		return
	}
	w, err := d.ensure()
	if err != nil {
		m.err = err.Error()
		return
	}
	if m.settings.Scope != d.scope || m.settings.Epoch != view.ReceiveEpoch {
		m.settings = fileServiceSettings{Scope: d.scope, Epoch: view.ReceiveEpoch, AutoSave: m.settings.AutoSave, Saved: m.settings.Saved, Exported: m.settings.Exported}
		if err := d.saveServiceSettings(); err != nil {
			m.err = err.Error()
			_ = w.Agent.StopServing()
			return
		}
	}
	if m.settings.Receiving && !w.Agent.Receiving() {
		if err := d.setReceiving(w, true); err != nil {
			m.err = err.Error()
			return
		}
	}
	if !m.settings.Receiving && w.Agent.Receiving() {
		if err := d.setReceiving(w, false); err != nil {
			m.err = err.Error()
			return
		}
	}
	m.err = ""
	if m.directory != "" && m.settings.AutoSave && !m.saving && time.Now().After(m.saveAfter) {
		for _, row := range w.Agent.List() {
			if row.Transfer.State != "completed" || m.settings.Exported[row.Transfer.ID] {
				continue
			}
			m.saving = true
			d.background.Add(1)
			go func(t filetransfer.Transfer) {
				defer d.background.Done()
				err := d.saveManagedFile(w, t)
				d.opMu.Lock()
				defer d.opMu.Unlock()
				m.saving = false
				m.saveAfter = time.Now().Add(2 * time.Second)
				previousError := m.saveError
				if err != nil {
					m.saveError = "cannot save received file: " + err.Error()
				} else {
					m.saveError = ""
				}
				if m.saveError != "" && m.saveError != previousError && d.ctx.Err() == nil {
					fmt.Fprintln(os.Stderr, "File service:", m.saveError)
				}
			}(row.Transfer)
			break
		}
	}
}

// File IO stays outside opMu so a large verified export cannot freeze the UI
// or block reception/cancellation controls. Journal mutations remain serialized.
func (d *desktopFileAgent) saveManagedFile(w *filetransfer.Workspace, t filetransfer.Transfer) error {
	d.opMu.Lock()
	m := d.managed
	if m.settings.Exported[t.ID] {
		d.opMu.Unlock()
		return nil
	}
	root, err := os.OpenRoot(m.directory)
	if err != nil {
		d.opMu.Unlock()
		return err
	}
	defer root.Close()
	if !browserName(t.Name) {
		d.opMu.Unlock()
		return errors.New("invalid received name")
	}
	name := m.settings.Saved[t.ID]
	recovering := name != ""
	if name == "" {
		for n := 0; n < 1000; n++ {
			candidate := t.Name
			if n > 0 {
				ext := filepath.Ext(candidate)
				candidate = strings.TrimSuffix(candidate, ext) + fmt.Sprintf(" (%d)", n) + ext
			}
			if _, e := root.Lstat(candidate); errors.Is(e, os.ErrNotExist) {
				name = candidate
				break
			} else if e != nil {
				d.opMu.Unlock()
				return e
			}
		}
		if name == "" {
			d.opMu.Unlock()
			return errors.New("too many duplicate file names")
		}
		m.settings.Saved[t.ID] = name
		if err = d.saveServiceSettings(); err != nil {
			delete(m.settings.Saved, t.ID)
			d.opMu.Unlock()
			return err
		}
	}
	d.opMu.Unlock()
	tmp := ".calabi-" + t.ID + ".saving"
	defer root.Remove(tmp)
	if recovering {
		f, e := root.Open(name)
		if e == nil {
			info, e := f.Stat()
			if e != nil || !info.Mode().IsRegular() {
				f.Close()
				return errors.New("saved path is not a regular file")
			}
			h := sha256.New()
			n, e := io.Copy(h, f)
			f.Close()
			if e != nil {
				return e
			}
			if n != t.Size || hex.EncodeToString(h.Sum(nil)) != t.SHA256 {
				return errors.New("saved file changed; retained original received data")
			}
			d.opMu.Lock()
			defer d.opMu.Unlock()
			m.settings.Exported[t.ID] = true
			if e = d.saveServiceSettings(); e != nil {
				delete(m.settings.Exported, t.ID)
			}
			return e
		}
		if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		_ = root.Remove(tmp) // only this journaled internal staging name
	}
	f, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err == nil {
		err = w.Agent.CopyCompleted(w.Context(), t.ID, f)
		if err == nil {
			err = f.Sync()
		}
		err = errors.Join(err, f.Close())
		if err == nil {
			err = w.Context().Err()
		}
		if err == nil {
			err = root.Link(tmp, name)
		} // no replacement of any existing path
	}
	d.opMu.Lock()
	defer d.opMu.Unlock()
	if err != nil {
		delete(m.settings.Saved, t.ID)
		_ = d.saveServiceSettings()
		return err
	}
	m.settings.Exported[t.ID] = true
	if err = d.saveServiceSettings(); err != nil {
		delete(m.settings.Exported, t.ID)
	}
	return err
}
