package filetransfer

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Source records are private user metadata. Never expose Local through Staged()
// or metadata IPC; the privileged service must not receive source paths.
type sourceRecord struct {
	StagedFile
	Local *localSource `json:"local,omitempty"`
}

type localSource struct {
	Path     string `json:"path"`
	Identity string `json:"identity"`
	Modified int64  `json:"modified"`
}

func (s localSource) valid() bool { return filepath.IsAbs(s.Path) && s.Identity != "" }

var errLocalSource = errors.New("original file changed or is unavailable; remove this source and select the file again")

// ReferenceLocal authorizes an explicitly selected local file without copying
// or hashing its contents. Streams/URI providers can continue using Stage.
func (w *Workspace) ReferenceLocal(ctx context.Context, path string) (StagedFile, error) {
	return w.referenceLocal(ctx, path, nil)
}

// ReferenceLocalChecked binds selection to a file already opened through a
// restricted directory, preventing a path replacement during registration.
func (w *Workspace) ReferenceLocalChecked(ctx context.Context, path string, selected os.FileInfo) (StagedFile, error) {
	if selected == nil {
		return StagedFile{}, errLocalSource
	}
	return w.referenceLocal(ctx, path, selected)
}

func (w *Workspace) referenceLocal(ctx context.Context, path string, selected os.FileInfo) (StagedFile, error) {
	w.stageMu.Lock()
	defer w.stageMu.Unlock()
	var zero StagedFile
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return zero, err
	}
	name := filepath.Base(path)
	// Resolve the selected target once, so later symlink changes cannot redirect it.
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return zero, errLocalSource
	}
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() {
		return zero, errLocalSource
	}
	f, err := openLocalSource(path)
	if err != nil {
		return zero, errLocalSource
	}
	defer f.Close()
	st, err = f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return zero, errLocalSource
	}
	if selected != nil && !os.SameFile(selected, st) {
		return zero, errLocalSource
	}
	identity, err := localFileIdentity(f, st)
	if err != nil {
		return zero, err
	}
	s := StagedFile{ID: randomID(), Name: name, Size: st.Size(), CreatedUnixMs: time.Now().UnixMilli()}
	if !validName(s.Name) || s.Size < 0 {
		return zero, errLocalSource
	}
	local := localSource{Path: path, Identity: identity, Modified: st.ModTime().UnixNano()}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return zero, errors.New("workspace closed")
	}
	var used int64
	for _, item := range w.sources {
		used += item.Size
	}
	if len(w.sources) >= MaxBatchFiles || s.Size > w.Agent.cfg.MaxBytes-used {
		return zero, errors.New("source quota exceeded; remove unused source records")
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if err := writeRecord(w.root, "source-"+s.ID+".json", sourceRecord{StagedFile: s, Local: &local}); err != nil {
		return zero, err
	}
	if w.localSources == nil {
		w.localSources = make(map[string]localSource)
	}
	w.localSources[s.ID] = local
	w.sources[s.ID] = s
	return s, nil
}

func (s localSource) open(size int64) (*checkedLocalFile, error) {
	f, err := openLocalSource(s.Path)
	if err != nil {
		return nil, errLocalSource
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() != size || st.ModTime().UnixNano() != s.Modified {
		f.Close()
		return nil, errLocalSource
	}
	identity, err := localFileIdentity(f, st)
	if err != nil || identity != s.Identity {
		f.Close()
		return nil, errLocalSource
	}
	return &checkedLocalFile{File: f, size: size, modified: s.Modified}, nil
}

type checkedLocalFile struct {
	*os.File
	mu       sync.Mutex
	size     int64
	modified int64
}

func (f *checkedLocalFile) check() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.checkLocked()
}

func (f *checkedLocalFile) checkLocked() error {
	st, err := f.File.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() != f.size || st.ModTime().UnixNano() != f.modified {
		return errLocalSource
	}
	return nil
}
func (f *checkedLocalFile) Read(p []byte) (int, error) {
	if err := f.check(); err != nil {
		return 0, err
	}
	n, err := f.File.Read(p)
	if changed := f.check(); changed != nil {
		return 0, changed
	}
	return n, err
}
func (f *checkedLocalFile) Seek(offset int64, whence int) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.checkLocked(); err != nil {
		return 0, err
	}
	return f.File.Seek(offset, whence)
}

func (f *checkedLocalFile) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.File.Close()
}

var _ io.ReadSeekCloser = (*checkedLocalFile)(nil)
