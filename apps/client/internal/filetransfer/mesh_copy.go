package filetransfer

// Session-scoped, pull-only clipboard files. No ordinary inbox/jobs, and no
// file bytes in RDP. All HTTP calls retain the agent's mutual TLS and mesh bind.
import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
)

const copyLease = 12 * time.Second

var (
	ErrCopySessionEnded     = errors.New("copy session ended")
	ErrCopyOfferUnavailable = errors.New("copy offer unavailable")
	ErrCopySourceRead       = errors.New("copy source changed or could not be read")
)

type copyFile struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}
type copyMessage struct {
	Op      string     `json:"op"`
	Session string     `json:"session"`
	Offer   string     `json:"offer,omitempty"`
	Files   []copyFile `json:"files,omitempty"`
	Index   int        `json:"index,omitempty"`
	Offset  int64      `json:"offset,omitempty"`
	Count   int        `json:"count,omitempty"`
}
type copySource struct {
	file *os.File
	stat os.FileInfo
}
type copyPending struct {
	key    copyMessage
	data   []byte
	err    error
	done   bool
	cancel context.CancelFunc
}
type meshCopySession struct {
	id       string
	grant    Grant
	host     bool
	until    time.Time
	ctx      context.Context
	cancel   context.CancelFunc
	sender   *Sender
	sourceID string
	sources  []copySource
	incoming string
	files    []copyFile
	pending  *copyPending
}
type CopySnapshot struct {
	Session, PeerIP, Offer string
	Host                   bool
	Manifest               []byte
}

func copyID() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return ""
	}
	return hex.EncodeToString(b)
}
func (a *Agent) dropCopyLocked() {
	s := a.copySession
	if s == nil {
		return
	}
	a.copySession = nil
	s.cancel()
	s.sender.Close()
	if s.pending != nil {
		s.pending.cancel()
	}
	for _, f := range s.sources {
		f.file.Close()
	}
}
func (a *Agent) copyLiveLocked(id string) *meshCopySession {
	s := a.copySession
	if s == nil {
		return nil
	}
	now, ok := a.cfg.Resolve(s.grant.Peer.IP)
	if a.closed.Load() || s.ctx.Err() != nil || !time.Now().Before(s.until) || !ok || now.DeviceKey != s.grant.DeviceKey || now.Peer.Fingerprint != s.grant.Peer.Fingerprint || a.cfg.ClipboardPeer == nil || !a.cfg.ClipboardPeer(now) || (a.cfg.Authority != nil && !a.cfg.Authority()) {
		a.dropCopyLocked()
		return nil
	}
	if id != "" && s.id != id {
		return nil
	}
	return s
}
func (a *Agent) newCopyLocked(g Grant, id string, host bool) (*meshCopySession, error) {
	if a.copyLiveLocked("") != nil {
		return nil, errors.New("another remote file-copy session is active")
	}
	sender, e := NewSender(a.cfg.Identity, a.cfg.LocalIP, g.Peer, int(g.Port), a.budget, func() bool { return !a.closed.Load() })
	if e != nil {
		return nil, e
	}
	sender.base = "https://" + netJoin(g.Peer.IP, int(g.Port)) + "/rdp-copy/v2"
	ctx, cancel := context.WithCancel(a.ctx)
	s := &meshCopySession{id: id, grant: g, host: host, until: time.Now().Add(copyLease), ctx: ctx, cancel: cancel, sender: sender}
	a.copySession = s
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.copyMu.Lock()
				a.copyLiveLocked(id)
				a.copyMu.Unlock()
			}
		}
	}()
	return s, nil
}
func copyCall(ctx context.Context, s *meshCopySession, m copyMessage) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	body, _ := json.Marshal(m)
	r, e := http.NewRequestWithContext(ctx, "POST", s.sender.base, bytes.NewReader(body))
	if e != nil {
		return nil, e
	}
	r.Header.Set("Content-Type", "application/json")
	resp, e := s.sender.control.Do(r)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		if m.Op == "read" && resp.StatusCode == http.StatusConflict {
			return nil, ErrCopySourceRead
		}
		return nil, fmt.Errorf("remote copy HTTP %d", resp.StatusCode)
	}
	data, e := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if e != nil {
		return nil, fmt.Errorf("read remote copy response: %w", e)
	}
	if len(data) > 65536 {
		return nil, errors.New("invalid remote copy response")
	}
	if m.Op == "read" {
		sum := sha256.Sum256(data)
		if len(data) != m.Count || resp.Header.Get("X-Calabi-Block-SHA256") != hex.EncodeToString(sum[:]) {
			return nil, errors.New("remote copy block mismatch")
		}
	}
	return data, nil
}
func (a *Agent) CopyStart(ctx context.Context, ip netip.Addr) (string, error) {
	g, ok := a.cfg.Resolve(ip)
	if !ok || a.cfg.ClipboardPeer == nil || !a.cfg.ClipboardPeer(g) {
		return "", errors.New("owned online copy peer required")
	}
	id := copyID()
	if id == "" {
		return "", errors.New("cannot create copy session")
	}
	a.copyMu.Lock()
	s, e := a.newCopyLocked(g, id, false)
	a.copyMu.Unlock()
	if e != nil {
		return "", e
	}
	if _, e = copyCall(ctx, s, copyMessage{Op: "start", Session: id}); e != nil {
		a.copyMu.Lock()
		if a.copySession == s {
			a.dropCopyLocked()
		}
		a.copyMu.Unlock()
		return "", e
	}
	return id, nil
}
func (a *Agent) CopyRenew(ctx context.Context, id string) error {
	a.copyMu.Lock()
	s := a.copyLiveLocked(id)
	if s == nil || s.host {
		a.copyMu.Unlock()
		return errors.New("copy session ended")
	}
	a.copyMu.Unlock()
	_, e := copyCall(ctx, s, copyMessage{Op: "renew", Session: id})
	a.copyMu.Lock()
	defer a.copyMu.Unlock()
	if a.copySession != s {
		return errors.New("copy session changed")
	}
	if e != nil {
		a.dropCopyLocked()
		return e
	}
	s.until = time.Now().Add(copyLease)
	return nil
}
func (a *Agent) CopyClose(ctx context.Context, id string) {
	a.copyMu.Lock()
	s := a.copyLiveLocked(id)
	if s != nil {
		a.dropCopyLocked()
	}
	a.copyMu.Unlock()
	if s != nil {
		// Local reads stop immediately, even if the peer cannot be reached.
		notification := &meshCopySession{ctx: ctx, sender: s.sender}
		_, _ = copyCall(ctx, notification, copyMessage{Op: "close", Session: id})
		s.sender.Close()
	}
}
func copyManifest(files []copyFile) []byte {
	data := make([]byte, 4+592*len(files))
	binary.LittleEndian.PutUint32(data, uint32(len(files)))
	for i, f := range files {
		d := data[4+592*i:]
		binary.LittleEndian.PutUint32(d, 0x80000044)
		binary.LittleEndian.PutUint32(d[36:], 0x80)
		binary.LittleEndian.PutUint32(d[64:], uint32(uint64(f.Size)>>32))
		binary.LittleEndian.PutUint32(d[68:], uint32(f.Size))
		for j, u := range utf16.Encode([]rune(f.Name)) {
			binary.LittleEndian.PutUint16(d[72+j*2:], u)
		}
	}
	return data
}
func validateCopyFiles(files []copyFile) bool {
	if len(files) < 1 || len(files) > 32 {
		return false
	}
	var total int64
	names := map[string]bool{}
	for _, f := range files {
		n := strings.ToLower(f.Name)
		stem := strings.ToUpper(strings.SplitN(f.Name, ".", 2)[0])
		if stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" || stem == "CONIN$" || stem == "CONOUT$" || (len(stem) == 4 && (strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT"))) {
			return false
		}
		if !validName(f.Name) || len(utf16.Encode([]rune(f.Name))) >= 260 || strings.ContainsAny(f.Name, `<>:"/\|?*`) || strings.HasSuffix(f.Name, ".") || strings.HasSuffix(f.Name, " ") || names[n] || f.Size < 0 || f.Size > ShellPasteLimit-total {
			return false
		}
		names[n] = true
		total += f.Size
	}
	return true
}
func (a *Agent) CopySnapshot() CopySnapshot {
	a.copyMu.Lock()
	defer a.copyMu.Unlock()
	s := a.copyLiveLocked("")
	if s == nil {
		return CopySnapshot{}
	}
	return CopySnapshot{Session: s.id, PeerIP: s.grant.Peer.IP.String(), Host: s.host, Offer: s.incoming, Manifest: copyManifest(s.files)}
}
func (a *Agent) CopyOffer(ctx context.Context, id string, paths []string) error {
	if len(paths) < 1 || len(paths) > 32 {
		return errors.New("invalid copy selection")
	}
	var sources []copySource
	var files []copyFile
	keep := false
	defer func() {
		if !keep {
			for _, f := range sources {
				f.file.Close()
			}
		}
	}()
	for _, path := range paths {
		st, e := os.Lstat(path)
		if e != nil || !filepath.IsAbs(path) || !st.Mode().IsRegular() {
			return errors.New("ordinary files required")
		}
		f, e := os.Open(path)
		if e != nil {
			return e
		}
		now, e := f.Stat()
		if e != nil || !os.SameFile(st, now) {
			f.Close()
			return errors.New("source changed")
		}
		sources = append(sources, copySource{f, now})
		files = append(files, copyFile{filepath.Base(path), now.Size()})
	}
	if !validateCopyFiles(files) {
		return errors.New("invalid copy manifest")
	}
	offer := copyID()
	if offer == "" {
		return errors.New("copy id unavailable")
	}
	a.copyMu.Lock()
	s := a.copyLiveLocked(id)
	if s == nil {
		a.copyMu.Unlock()
		return errors.New("copy session ended")
	}
	for _, f := range s.sources {
		f.file.Close()
	}
	s.sources = sources
	s.sourceID = offer
	keep = true
	a.copyMu.Unlock()
	_, e := copyCall(ctx, s, copyMessage{Op: "offer", Session: id, Offer: offer, Files: files})
	if e != nil {
		a.copyMu.Lock()
		if a.copySession == s && s.sourceID == offer {
			for _, f := range s.sources {
				f.file.Close()
			}
			s.sources = nil
			s.sourceID = ""
		}
		a.copyMu.Unlock()
	}
	return e
}
func (a *Agent) CopyRead(offer string, index int, offset int64, count int) ([]byte, bool, error) {
	a.copyMu.Lock()
	defer a.copyMu.Unlock()
	s := a.copyLiveLocked("")
	if s == nil {
		return nil, false, ErrCopySessionEnded
	}
	if s.incoming == "" || s.incoming != offer {
		return nil, false, ErrCopyOfferUnavailable
	}
	if index < 0 || index >= len(s.files) || count < 1 || count > 65536 || offset < 0 || offset > s.files[index].Size-int64(count) {
		return nil, false, errors.New("copy read denied")
	}
	key := copyMessage{Op: "read", Session: s.id, Offer: offer, Index: index, Offset: offset, Count: count}
	if p := s.pending; p != nil {
		if p.key.Offer != offer || p.key.Index != index || p.key.Offset != offset || p.key.Count != count {
			return nil, false, errors.New("another read pending")
		}
		if !p.done {
			return nil, true, nil
		}
		s.pending = nil
		p.cancel()
		return p.data, false, p.err
	}
	ctx, cancel := context.WithCancel(s.ctx)
	p := &copyPending{key: key, cancel: cancel}
	s.pending = p
	go func() {
		data, e := copyCall(ctx, s, key)
		a.copyMu.Lock()
		defer a.copyMu.Unlock()
		if a.copySession == s && s.pending == p {
			p.data, p.err, p.done = data, e, true
		}
	}()
	return nil, true, nil
}
func (a *Agent) CopyCancel(offer string) {
	a.copyMu.Lock()
	s := a.copyLiveLocked("")
	if s == nil || s.incoming != offer {
		a.copyMu.Unlock()
		return
	}
	s.incoming = ""
	s.files = nil
	if s.pending != nil {
		s.pending.cancel()
		s.pending = nil
	}
	a.copyMu.Unlock()
	go func() { _, _ = copyCall(s.ctx, s, copyMessage{Op: "cancel", Session: s.id, Offer: offer}) }()
}

func (a *Agent) CopyClear(ctx context.Context, id string) {
	a.copyMu.Lock()
	s := a.copyLiveLocked(id)
	if s == nil {
		a.copyMu.Unlock()
		return
	}
	offer := s.sourceID
	for _, f := range s.sources {
		f.file.Close()
	}
	s.sources = nil
	s.sourceID = ""
	a.copyMu.Unlock()
	if offer != "" {
		_, _ = copyCall(ctx, s, copyMessage{Op: "revoke", Session: id, Offer: offer})
	}
}
func (a *Agent) serveMeshCopy(g Grant, w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		fail(w, 405, "POST required")
		return
	}
	var m copyMessage
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 32768)).Decode(&m) != nil || !validID(m.Session) {
		fail(w, 400, "invalid copy request")
		return
	}
	a.copyMu.Lock()
	s := a.copyLiveLocked(m.Session)
	if m.Op == "start" {
		if s != nil && s.grant.DeviceKey == g.DeviceKey && s.host {
			s.until = time.Now().Add(copyLease)
		} else {
			var e error
			s, e = a.newCopyLocked(g, m.Session, true)
			if e != nil {
				a.copyMu.Unlock()
				fail(w, 409, "copy session busy")
				return
			}
		}
		a.copyMu.Unlock()
		w.WriteHeader(200)
		return
	}
	if s == nil || s.grant.DeviceKey != g.DeviceKey || s.grant.Peer.IP != g.Peer.IP {
		a.copyMu.Unlock()
		fail(w, 403, "copy session unavailable")
		return
	}
	switch m.Op {
	case "renew":
		if !s.host {
			a.copyMu.Unlock()
			fail(w, 403, "not a host session")
			return
		}
		s.until = time.Now().Add(copyLease)
	case "close":
		a.dropCopyLocked()
	case "offer":
		if !validID(m.Offer) || !validateCopyFiles(m.Files) {
			a.copyMu.Unlock()
			fail(w, 400, "invalid file manifest")
			return
		}
		if s.pending != nil {
			s.pending.cancel()
			s.pending = nil
		}
		s.incoming = m.Offer
		s.files = m.Files
	case "cancel":
		if s.sourceID == m.Offer {
			for _, f := range s.sources {
				f.file.Close()
			}
			s.sources = nil
			s.sourceID = ""
		}
	case "revoke":
		if s.incoming == m.Offer {
			s.incoming = ""
			s.files = nil
			if s.pending != nil {
				s.pending.cancel()
				s.pending = nil
			}
		}
	case "read":
		if s.sourceID != m.Offer || !validID(m.Offer) || m.Index < 0 || m.Index >= len(s.sources) || m.Count < 1 || m.Count > 65536 {
			a.copyMu.Unlock()
			fail(w, 403, "copy source unavailable")
			return
		}
		f := s.sources[m.Index]
		now, e := f.file.Stat()
		if e != nil || now.Size() != f.stat.Size() || !now.ModTime().Equal(f.stat.ModTime()) || m.Offset < 0 || m.Offset > f.stat.Size()-int64(m.Count) {
			a.copyMu.Unlock()
			fail(w, 409, "source changed")
			return
		}
		data := make([]byte, m.Count)
		_, e = f.file.ReadAt(data, m.Offset)
		after, statErr := f.file.Stat()
		if statErr != nil || after.Size() != f.stat.Size() || !after.ModTime().Equal(f.stat.ModTime()) {
			e = errors.New("source changed")
		}
		a.copyMu.Unlock()
		if e != nil {
			fail(w, 409, "source read failed")
			return
		}
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		stop := context.AfterFunc(s.ctx, cancel)
		defer stop()
		sum := sha256.Sum256(data)
		w.Header().Set("X-Calabi-Block-SHA256", hex.EncodeToString(sum[:]))
		w.Header().Set("Content-Type", "application/octet-stream")
		for len(data) > 0 {
			n := min(len(data), paceChunk)
			if a.budget.Wait(ctx, n) != nil {
				return
			}
			if relay := a.pathBudget(g.Peer.IP); relay != nil && relay.Wait(ctx, n) != nil {
				return
			}
			if _, e = w.Write(data[:n]); e != nil {
				return
			}
			data = data[n:]
		}
		return
	default:
		a.copyMu.Unlock()
		fail(w, 400, "unknown copy operation")
		return
	}
	a.copyMu.Unlock()
	w.WriteHeader(200)
}
