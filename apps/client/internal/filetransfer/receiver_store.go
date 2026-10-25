package filetransfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

type receiveRecord struct {
	Version  int       `json:"version"`
	Scope    string    `json:"scope"`
	Peer     Peer      `json:"peer"`
	Transfer Transfer  `json:"transfer"`
	Token    string    `json:"token"`
	Created  time.Time `json:"created"`
}

func validID(id string) bool {
	b, err := hex.DecodeString(id)
	return err == nil && len(b) == 32 && strings.ToLower(id) == id
}

// writeRecord only takes internal names. Sync precedes rename: acknowledged
// offsets never depend on a partially written JSON document after a crash.
func writeRecord(root *os.Root, name string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	tmp := randomID() + ".tmp"
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(tmp)
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return root.Rename(tmp, name)
}

// Caller holds the session lock (or has not published a newly created one).
func (r *Receiver) persist(s *receiveSession) error {
	if !r.cfg.Durable {
		s.publish()
		return nil
	}
	err := writeRecord(r.root, s.ID+".json", receiveRecord{Version: 1, Scope: r.cfg.Scope, Peer: r.cfg.Peer, Transfer: s.Transfer, Token: s.token, Created: s.created})
	if err == nil {
		s.publish()
	}
	return err
}

func (r *Receiver) restore() error {
	dir, err := r.root.Open(".")
	if err != nil {
		return err
	}
	entries, err := dir.ReadDir(-1)
	dir.Close()
	if err != nil {
		return err
	}
	var reserved int64
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		if !validID(id) {
			continue
		}
		if len(r.sessions) >= 32 {
			return errors.New("durable inbox record limit exceeded")
		}
		f, err := r.root.Open(e.Name())
		if err != nil {
			return err
		}
		var record receiveRecord
		err = json.NewDecoder(io.LimitReader(f, 8193)).Decode(&record)
		f.Close()
		if err != nil {
			return fmt.Errorf("invalid inbox record %s", id)
		}
		t := record.Transfer
		t.RateBps = 0
		t.RemainingSeconds = 0
		if record.Version != 1 || record.Scope != r.cfg.Scope || record.Peer != r.cfg.Peer {
			return errors.New("inbox belongs to another identity or organization")
		}
		if t.ID != id || t.BatchCount < 1 || t.BatchCount > MaxBatchFiles || !validID(t.ClientID) || !validID(record.Token) || !validName(t.Name) || t.Size < 0 || t.Offset < 0 || t.Offset > t.Size || !validID(t.SHA256) || !validID(t.Batch) || record.Created.IsZero() || record.Created.After(time.Now().Add(time.Minute)) {
			return errors.New("invalid durable transfer metadata")
		}
		// Original rate/limits are never a way to escape today's budget.
		t.Kbps = r.cfg.Kbps
		t.MaxBlock = max(paceChunk, min(BlockSize, r.cfg.Kbps*128))
		ctx, cancel := context.WithDeadline(r.ctx, record.Created.Add(24*time.Hour))
		s := &receiveSession{Transfer: t, token: record.Token, created: record.Created, ctx: ctx, cancel: cancel}
		switch t.State {
		case "completed", "committing":
			if t.Offset != t.Size {
				cancel()
				return errors.New("invalid completed size")
			}
			if t.State == "completed" {
				st, err := r.root.Stat(id + ".received")
				if err != nil || !st.Mode().IsRegular() || st.Size() != t.Size {
					cancel()
					return errors.New("completed inbox file is unavailable or changed")
				}
				s.StoredName = id + ".received"
				break // CopyCompleted rechecks SHA-256 while exporting; no full inbox rescan at startup.
			}
			// If the process died around rename, rehash before recovering a
			// receipt. A .received file alone is never treated as completed.
			name := id + ".received"
			if t.State == "committing" {
				if _, err := r.root.Stat(name); errors.Is(err, os.ErrNotExist) {
					name = id + ".part"
				}
			}
			f, err := r.root.Open(name)
			if err != nil {
				cancel()
				return err
			}
			h := sha256.New()
			n, err := io.Copy(h, io.LimitReader(f, t.Size+1))
			f.Close()
			if err != nil || n != t.Size || hex.EncodeToString(h.Sum(nil)) != t.SHA256 {
				cancel()
				return errors.New("recovered file checksum mismatch")
			}
			if name != id+".received" {
				if err := r.root.Rename(name, id+".received"); err != nil {
					cancel()
					return err
				}
			}
			s.State = "completed"
			s.StoredName = id + ".received"
		case "accepted", "receiving", "paused":
			if ctx.Err() != nil {
				s.State = "cancelled"
				_ = r.root.Remove(id + ".part")
				break
			}
			f, err := r.root.OpenFile(id+".part", os.O_WRONLY, 0)
			if err != nil {
				cancel()
				return err
			}
			st, err := f.Stat()
			if err == nil && st.Size() < t.Offset {
				err = errors.New("persisted file shorter than acknowledged offset")
			}
			if err == nil {
				err = f.Truncate(t.Offset)
			}
			f.Close()
			if err != nil {
				cancel()
				return err
			}
		case "waiting":
			_ = r.root.Remove(id + ".part") // crash between file creation and acceptance
			if ctx.Err() != nil {
				s.State = "cancelled"
			}
		case "cancelled", "failed":
			_ = r.root.Remove(id + ".part")
		default:
			cancel()
			return errors.New("invalid durable transfer state")
		}
		if s.State != "cancelled" && s.State != "failed" {
			if t.Size > r.cfg.MaxBytes-reserved {
				cancel()
				return errors.New("recovered inbox exceeds current limit")
			}
			reserved += t.Size
		}
		if err := r.persist(s); err != nil {
			cancel()
			return err
		}
		r.sessions[id] = s
		s.lastActivity.Store(time.Now().UnixNano())
		r.interrupts.Store(id, s.cancel)
	}
	return nil
}

// Forget removes only a terminal transfer selected by this user. Removing the
// manifest first cannot turn a deleted file into a successful recovery receipt.
func (r *Receiver) Forget(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.sessions[id]
	if s == nil {
		return errors.New("unknown transfer")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.State != "completed" && s.State != "cancelled" && s.State != "failed" {
		return errors.New("cancel the active transfer first")
	}
	if r.cfg.Durable {
		if err := r.root.Remove(id + ".json"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	for _, suffix := range []string{".part", ".received"} {
		if err := r.root.Remove(id + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	s.cancel()
	delete(r.sessions, id)
	r.interrupts.Delete(id)
	return nil
}

func (r *Receiver) Interrupt() {
	r.interrupts.Range(func(_, cancel any) bool { cancel.(context.CancelFunc)(); return true })
}

func (r *Receiver) CancelIncomplete() error {
	r.Interrupt()
	var errs []error
	for _, t := range r.List() {
		if t.State != "completed" && t.State != "cancelled" && t.State != "failed" {
			if err := r.Cancel(t.ID); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
