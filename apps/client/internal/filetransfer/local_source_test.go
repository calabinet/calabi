package filetransfer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func localReferenceConfig(t *testing.T) AgentConfig {
	t.Helper()
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return AgentConfig{Identity: id, Directory: t.TempDir(), Scope: "test/refs", LocalIP: netip.MustParseAddr("127.0.0.1"), Port: 17401, Kbps: 32768, MaxBytes: 8 << 20, Resolve: func(netip.Addr) (Grant, bool) { return Grant{}, false }, Incoming: func(netip.Addr, uint16) bool { return true }}
}

func TestLocalReferenceHasNoCopyAndNeverDeletesOriginal(t *testing.T) {
	cfg := localReferenceConfig(t)
	w, err := NewWorkspace(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	path := filepath.Join(t.TempDir(), "original-中文.bin")
	data := bytes.Repeat([]byte("unchanged"), 10000)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := w.ReferenceLocal(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cfg.Directory, "source-"+s.ID+".bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("original was copied into cache")
	}
	view, _ := json.Marshal(w.Staged())
	if bytes.Contains(view, []byte("local")) || bytes.Contains(view, []byte("path")) || bytes.Contains(view, []byte("identity")) {
		t.Fatalf("private source metadata leaked to UI: %s", view)
	}
	// Legacy stream sources still use their private cache and coexist with references.
	cached, err := w.Stage(context.Background(), bytes.NewReader([]byte("cached")), "stream.txt", 6)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w, err = NewWorkspace(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if len(w.Staged()) != 2 {
		t.Fatal("cached/reference metadata not restored")
	}
	f, err := w.localSources[s.ID].open(s.Size)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(f)
	f.Close()
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("reference read changed original bytes", err)
	}
	if err := w.ForgetSource(s.ID); err != nil {
		t.Fatal(err)
	}
	if err := w.ForgetSource(cached.ID); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("forget touched original", err)
	}
}

func TestLocalReferenceRejectsChangedReplacedAndMissingOriginal(t *testing.T) {
	for _, change := range []string{"modified", "replaced", "removed"} {
		t.Run(change, func(t *testing.T) {
			cfg := localReferenceConfig(t)
			w, err := NewWorkspace(cfg)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "file.bin")
			if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
				t.Fatal(err)
			}
			s, err := w.ReferenceLocal(context.Background(), path)
			if err != nil {
				t.Fatal(err)
			}
			st, _ := os.Stat(path)
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "modified":
				if err := os.WriteFile(path, []byte("new"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(path, st.ModTime().Add(time.Hour), st.ModTime().Add(time.Hour)); err != nil {
					t.Fatal(err)
				}
			case "replaced":
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("new"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(path, st.ModTime(), st.ModTime()); err != nil {
					t.Fatal(err)
				}
			case "removed":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			w, err = NewWorkspace(cfg)
			if err != nil {
				t.Fatal("unavailable source disabled the entire file centre", err)
			}
			defer w.Close()
			if _, err := w.Send(cfg.LocalIP, []string{s.ID}, ""); !errors.Is(err, errLocalSource) {
				t.Fatalf("unsafe source accepted: %v", err)
			}
		})
	}
}

func TestLocalReferenceDetectsModificationWhileOpen(t *testing.T) {
	cfg := localReferenceConfig(t)
	w, err := NewWorkspace(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	path := filepath.Join(t.TempDir(), "file.bin")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := w.ReferenceLocal(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := w.localSources[s.ID].open(s.Size)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := os.WriteFile(path, []byte("larger"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Read(make([]byte, 8)); !errors.Is(err, errLocalSource) {
		t.Fatal("changed open handle still read", err)
	}
}

func TestLocalReferenceResumesSameTransferAfterWorkspaceRestart(t *testing.T) {
	cfg := localReferenceConfig(t)
	remote, _ := NewIdentity()
	r, err := NewReceiver(ReceiverConfig{Peer: Peer{IP: cfg.LocalIP, Fingerprint: cfg.Identity.Fingerprint}, Directory: t.TempDir(), Kbps: 2048, MaxBytes: 8 << 20, Allowed: func() bool { return true }, Durable: true, Scope: "remote"})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, done := r.Serve(l, remote)
	defer func() { srv.Close(); <-done }()
	cfg.Resolve = func(netip.Addr) (Grant, bool) {
		return Grant{Path: "direct", Peer: Peer{IP: cfg.LocalIP, Fingerprint: remote.Fingerprint}, DeviceKey: "remote", Port: uint16(l.Addr().(*net.TCPAddr).Port), Receiving: true}, true
	}
	w, err := NewWorkspace(cfg)
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("resumable"), 100000)
	path := filepath.Join(t.TempDir(), "original.bin")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	originalInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	source, err := w.ReferenceLocal(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	job, err := w.Send(cfg.LocalIP, []string{source.ID}, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for len(r.List()) == 0 && ctx.Err() == nil {
		time.Sleep(time.Millisecond)
	}
	if len(r.List()) != 1 {
		w.Close()
		t.Fatal("offer not received")
	}
	before := r.List()[0]
	if err := r.Decide(before.ID, true); err != nil {
		w.Close()
		t.Fatal(err)
	}
	for r.List()[0].Offset == 0 && ctx.Err() == nil {
		time.Sleep(time.Millisecond)
	}
	if err := w.Pause(job); err != nil {
		w.Close()
		t.Fatal(err)
	}
	if got := w.Jobs()[0].Error; got != "" {
		w.Close()
		t.Fatalf("manual pause was misreported as a source failure: %s", got)
	}
	partial := r.List()[0].Offset
	confirmedProgress := w.Jobs()[0].Progress
	if partial == 0 || partial >= int64(len(data)) {
		w.Close()
		t.Fatal("test did not pause a partial transfer", partial)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w, err = NewWorkspace(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	// Even a same-size edit with restored mtime must fail resume's content hash.
	changed := append([]byte(nil), data...)
	changed[0] ^= 1
	if err := os.WriteFile(path, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, originalInfo.ModTime(), originalInfo.ModTime()); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Send(cfg.LocalIP, nil, job); err != nil {
		t.Fatal(err)
	}
	for w.Jobs()[0].State == "sending" && ctx.Err() == nil {
		time.Sleep(time.Millisecond)
	}
	if w.Jobs()[0].State != "paused" || w.Jobs()[0].Error != "source changed; resume refused" {
		t.Fatalf("content change was not rejected: %+v", w.Jobs()[0])
	}
	if got := w.Jobs()[0].Progress; got.Transfer != confirmedProgress.Transfer || got.Index != confirmedProgress.Index {
		t.Fatal("resume hashing discarded persisted transfer progress")
	}
	if r.List()[0].Offset != partial {
		t.Fatal("changed source uploaded bytes before rejection")
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, originalInfo.ModTime(), originalInfo.ModTime()); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Send(cfg.LocalIP, nil, job); err != nil {
		t.Fatal(err)
	}
	for w.Jobs()[0].State == "sending" && ctx.Err() == nil {
		time.Sleep(time.Millisecond)
	}
	if w.Jobs()[0].State != "completed" {
		t.Fatalf("resume failed: %+v", w.Jobs()[0])
	}
	final := r.List()[0]
	if final.ID != before.ID || final.Batch != before.Batch || final.Offset != int64(len(data)) {
		t.Fatal("resume replaced the original transfer")
	}
	var out bytes.Buffer
	if err := r.CopyCompleted(ctx, final.ID, &out); err != nil || !bytes.Equal(out.Bytes(), data) {
		t.Fatal("resumed file differs", err)
	}
}

func TestLocalReferenceCheckedRejectsReplacement(t *testing.T) {
	w, err := NewWorkspace(localReferenceConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "selected.bin")
	if err = os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	selectedFile, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer selectedFile.Close()
	selected, err := selectedFile.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err = selectedFile.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(path, filepath.Join(dir, "previous.bin")); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte("replaced"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = w.ReferenceLocalChecked(context.Background(), path, selected); err == nil {
		t.Fatal("replaced source accepted")
	}
	currentFile, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer currentFile.Close()
	current, _ := currentFile.Stat()
	if _, err = w.ReferenceLocalChecked(context.Background(), path, current); err != nil {
		t.Fatal(err)
	}
}
