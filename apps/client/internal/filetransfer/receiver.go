package filetransfer

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// Each offer names one file. V1 submits a bounded batch of idempotent offers
// before waiting for local confirmation; retains its one-file limit.
type Offer struct {
	BatchCount int    `json:"batch_count,omitempty"`
	ClientID   string `json:"client_id,omitempty"`
	Batch      string `json:"batch,omitempty"`
	Name       string `json:"name"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
}

type Transfer struct {
	PauseSupported   bool   `json:"pause_supported,omitempty"`
	StopReason       string `json:"stop_reason,omitempty"`
	RateBps          int64  `json:"rate_bps,omitempty"`
	RemainingSeconds int64  `json:"remaining_seconds,omitempty"`
	BatchCount       int    `json:"batch_count,omitempty"`
	ClientID         string `json:"client_id,omitempty"`
	Batch            string `json:"batch,omitempty"`
	ID               string `json:"id"`
	Name             string `json:"name"`
	Size             int64  `json:"size"`
	Offset           int64  `json:"offset"`
	State            string `json:"state"`
	SHA256           string `json:"sha256"`
	// StoredName is a random internal name, never a remote-controlled path.
	StoredName string `json:"stored_name,omitempty"`
	Kbps       int    `json:"kbps"`
	MaxBlock   int    `json:"max_block"`
}

type offerReply struct {
	Transfer
	Token string `json:"token"`
}

type receiveSession struct {
	throughput     throughput
	pauseRequested atomic.Bool
	lastActivity   atomic.Int64
	uploading      atomic.Bool
	uploadMu       sync.Mutex
	uploadCancel   context.CancelFunc
	snapshot       atomic.Pointer[Transfer]
	mu             sync.Mutex
	Transfer
	token   string
	created time.Time
	cancel  context.CancelFunc
	ctx     context.Context
}

func (s *receiveSession) publish() { t := s.Transfer; s.snapshot.Store(&t) }
func (s *receiveSession) view() Transfer {
	if p := s.snapshot.Load(); p != nil {
		return *p
	}
	return Transfer{}
}

func (r *Receiver) visible(s *receiveSession) Transfer {
	t := s.view()
	if r.cfg.Durable {
		t.Kbps = min(r.cfg.Kbps, r.pacer.Ceiling())
		if r.cfg.RouteBudget != nil {
			if p := r.cfg.RouteBudget(); p != nil {
				t.Kbps = min(t.Kbps, p.Ceiling())
			}
		}
		t.MaxBlock = max(paceChunk, min(BlockSize, t.Kbps*128))
	}
	return t
}

type ReceiverConfig struct {
	// Durable enables v1 only. Scope binds state to coordinator/org/local node.
	// Each peer has its own private directory and receiver; the shared budget
	// and UploadGate still belong to the whole user agent.
	Durable    bool
	Scope      string
	UploadGate chan struct{}
	Peer       Peer
	Directory  string // trusted local user's private inbox; never supplied remotely
	Kbps       int
	MaxBytes   int64
	// Budget can be shared with the local sender, so simultaneous sending and
	// receiving draw from one device file budget. Nil creates a receive-only one.
	Budget      *Pacer
	RouteBudget func() *Pacer
	// Allowed must be re-evaluated on EVERY request, not just at TLS handshake.
	// Production callers must check current peer membership and local settings.
	Allowed func() bool
}

type Receiver struct {
	mu         sync.Mutex
	cfg        ReceiverConfig
	root       *os.Root
	sessions   map[string]*receiveSession
	interrupts sync.Map // id -> context.CancelFunc; cancellation never waits on a stalled upload
	pacer      *Pacer
	requests   *rate.Limiter
	ctx        context.Context
	cancel     context.CancelFunc
	closed     bool
	closeOnce  sync.Once
	closeErr   error
}

func NewReceiver(cfg ReceiverConfig) (*Receiver, error) {
	if err := cfg.Peer.Validate(); err != nil {
		return nil, err
	}
	if cfg.Allowed == nil {
		return nil, errors.New("current peer authorization callback required")
	}
	if cfg.MaxBytes <= 0 {
		return nil, errors.New("positive inbox byte limit required")
	}
	pacer, err := NewPacer(cfg.Kbps)
	if err != nil {
		return nil, err
	}
	if cfg.Budget != nil {
		pacer = cfg.Budget
		pacer.cap(cfg.Kbps)
	}
	root, err := os.OpenRoot(cfg.Directory)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &Receiver{cfg: cfg, root: root, pacer: pacer, sessions: make(map[string]*receiveSession), requests: rate.NewLimiter(2, 8), ctx: ctx, cancel: cancel}
	if cfg.Durable {
		r.requests = rate.NewLimiter(2, 32)
		if cfg.Scope == "" {
			cancel()
			root.Close()
			return nil, errors.New("durable receiver requires identity scope")
		}
		if err := r.restore(); err != nil {
			cancel()
			root.Close()
			return nil, err
		}
	}
	return r, nil
}

func randomID() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

func jsonOut(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}

func fail(w http.ResponseWriter, code int, message string) {
	jsonOut(w, code, map[string]string{"error": message})
}

func (r *Receiver) Handler() http.Handler {
	mux := http.NewServeMux()
	base := "/file/p0"
	if r.cfg.Durable {
		base = "/file/v1"
	}
	mux.HandleFunc("GET "+base+"/ping", func(w http.ResponseWriter, _ *http.Request) { jsonOut(w, 200, map[string]bool{"ok": true}) })
	mux.HandleFunc("POST "+base+"/offers", r.offer)
	mux.HandleFunc("GET "+base+"/transfers/{id}", r.status)
	mux.HandleFunc("PUT "+base+"/transfers/{id}", r.upload)
	mux.HandleFunc("POST "+base+"/transfers/{id}/commit", r.commit)
	mux.HandleFunc("DELETE "+base+"/transfers/{id}", r.cancelTransfer)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		addr, err := netip.ParseAddrPort(req.RemoteAddr)
		if err != nil || addr.Addr().Unmap() != r.cfg.Peer.IP.Unmap() || req.TLS == nil || checkCertificate(*req.TLS, r.cfg.Peer.Fingerprint) != nil {
			fail(w, http.StatusForbidden, "unpaired device")
			return
		}
		if r.ctx.Err() != nil || !r.cfg.Allowed() {
			fail(w, http.StatusForbidden, "file receiving is no longer authorized")
			return
		}
		mux.ServeHTTP(w, req)
	})
}

// Serve only accepts an explicitly bound listener. Callers must bind the current
// overlay address; there is no wildcard or LAN listener fallback.
func (r *Receiver) Serve(listener net.Listener, identity *Identity) (*http.Server, <-chan error) {
	srv := &http.Server{Handler: r.Handler(), TLSConfig: identity.ServerTLS(r.cfg.Peer),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 90 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 * 1024,
		BaseContext: func(net.Listener) context.Context { return r.ctx },
	}
	done := make(chan error, 1)
	go func() { done <- srv.ServeTLS(listener, "", "") }()
	return srv, done
}

func (r *Receiver) offer(w http.ResponseWriter, req *http.Request) {
	if !r.requests.Allow() {
		fail(w, 429, "too many offers")
		return
	}
	var o Offer
	dec := json.NewDecoder(http.MaxBytesReader(w, req.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&o); err != nil {
		fail(w, 400, "invalid offer")
		return
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		fail(w, 400, "invalid trailing data")
		return
	}
	hash, err := hex.DecodeString(o.SHA256)
	if r.cfg.Durable && (o.BatchCount < 1 || o.BatchCount > MaxBatchFiles || !validID(o.SHA256)) {
		fail(w, 400, "invalid batch metadata")
		return
	}
	if !validName(o.Name) || o.Size < 0 || o.Size > r.cfg.MaxBytes || err != nil || len(hash) != sha256.Size || (o.Batch != "" && (!r.cfg.Durable || !validID(o.Batch))) || (r.cfg.Durable && (!validID(o.ClientID) || !validID(o.Batch))) {
		fail(w, 400, "invalid file metadata or size limit")
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		fail(w, 503, "receiver closed")
		return
	}
	if r.cfg.Durable {
		for _, s := range r.sessions {
			t := s.view()
			if t.ClientID == o.ClientID {
				if t.Batch != o.Batch || t.BatchCount != o.BatchCount || t.Name != o.Name || t.Size != o.Size || t.SHA256 != o.SHA256 {
					fail(w, 409, "offer identifier reused with different metadata")
					return
				}
				if time.Since(s.created) > 24*time.Hour {
					fail(w, 410, "offer expired")
					return
				}
				if !t.PauseSupported && req.Header.Get("X-Calabi-File-Control") == "pause-v1" {
					s.mu.Lock()
					s.PauseSupported = true
					err := r.persist(s)
					s.mu.Unlock()
					if err != nil {
						fail(w, 500, "cannot persist sender capabilities")
						return
					}
				}
				jsonOut(w, 200, offerReply{Transfer: r.visible(s), Token: s.token})
				return
			}
		}
	}
	// There is one active/accepted/waiting file, bounding disk use and
	// preventing multiple remote offers from claiming the same free space.
	var reserved int64
	for id, s := range r.sessions {
		t := s.view()
		terminal := t.State == "completed" || t.State == "cancelled" || t.State == "failed"
		if !terminal && time.Since(s.created) > 24*time.Hour {
			s.cancel()
			s.mu.Lock()
			s.State = "cancelled"
			s.publish()
			s.mu.Unlock()
			_ = r.root.Remove(s.ID + ".part")
			terminal = true
		}
		completed := t.State == "completed"
		if completed {
			reserved += t.Size
		} else if r.cfg.Durable && !terminal {
			reserved += t.Size
		}
		if terminal && !completed {
			delete(r.sessions, id)
			r.interrupts.Delete(id)
			if r.cfg.Durable {
				_ = r.root.Remove(id + ".json")
			}
		} else if !terminal && !r.cfg.Durable {
			fail(w, 409, "another file is pending or active")
			return
		}
	}
	if len(r.sessions) >= 32 || o.Size > r.cfg.MaxBytes-reserved {
		fail(w, 409, "inbox limit reached; remove completed records before more transfers")
		return
	}
	ctx, cancel := context.WithTimeout(r.ctx, 24*time.Hour)
	kbps := r.cfg.Kbps
	if r.cfg.Durable {
		kbps = min(kbps, r.pacer.Ceiling())
	}
	s := &receiveSession{Transfer: Transfer{BatchCount: o.BatchCount, ClientID: o.ClientID, Batch: o.Batch, ID: randomID(), Name: o.Name, Size: o.Size, SHA256: o.SHA256, State: "waiting", Kbps: kbps, MaxBlock: max(paceChunk, min(BlockSize, kbps*128))}, token: randomID(), created: time.Now(), ctx: ctx, cancel: cancel}
	s.PauseSupported = r.cfg.Durable && req.Header.Get("X-Calabi-File-Control") == "pause-v1"
	if err := r.persist(s); err != nil {
		cancel()
		fail(w, 500, "cannot persist offer")
		return
	}
	r.sessions[s.ID] = s
	r.interrupts.Store(s.ID, s.cancel)
	jsonOut(w, 201, offerReply{Transfer: r.visible(s), Token: s.token})
}

func (r *Receiver) find(id string) *receiveSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sessions[id]
}

func (r *Receiver) authorized(w http.ResponseWriter, req *http.Request) *receiveSession {
	s := r.find(req.PathValue("id"))
	if s == nil {
		fail(w, 404, "unknown transfer")
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(req.Header.Get("Authorization")), []byte("Bearer "+s.token)) != 1 {
		fail(w, 403, "invalid transfer credential")
		return nil
	}
	if time.Since(s.created) > 24*time.Hour {
		_ = r.Cancel(s.ID)
		fail(w, http.StatusGone, "transfer credential expired")
		return nil
	}
	return s
}

func (r *Receiver) status(w http.ResponseWriter, req *http.Request) {
	s := r.authorized(w, req)
	if s == nil {
		return
	}
	jsonOut(w, 200, r.visible(s))
}

// List, Decide and Cancel are LOCAL operations; they are never registered on
// the peer listener. The embedding UI/CLI owns local user authorization.
func (r *Receiver) List() []Transfer {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []Transfer{}
	for _, s := range r.sessions {
		t := r.visible(s)
		// Inactivity is a local presentation hint, never a new wire state for
		// older senders. It does not claim that the remote user clicked Pause.
		if r.cfg.Durable && (t.State == "accepted" || t.State == "receiving") && !s.uploading.Load() && time.Since(time.Unix(0, s.lastActivity.Load())) > 5*time.Second {
			t.State = "waiting_sender"
			t.RateBps, t.RemainingSeconds = 0, 0
		}
		out = append(out, t)
	}
	slices.SortFunc(out, compareTransferOrder)
	return out
}

// Keep batches together and files in a fixed order, independent of live state.
// The ID tie-breaker also makes duplicate filenames deterministic.
func compareTransferOrder(a, b Transfer) int {
	return cmp.Or(cmp.Compare(a.Batch, b.Batch), cmp.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID))
}

func (r *Receiver) Decide(id string, accept bool) error {
	s := r.find(id)
	if s == nil {
		return errors.New("unknown transfer")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.State != "waiting" {
		return errors.New("transfer is no longer waiting")
	}
	if !accept {
		s.State = "cancelled"
		s.StopReason = "receiver_rejected"
		s.cancel()
		return r.persist(s)
	}
	if r.ctx.Err() != nil || !r.cfg.Allowed() {
		return errors.New("file receiving is no longer authorized")
	}
	f, err := r.root.OpenFile(id+".part", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		_ = r.root.Remove(id + ".part")
		return err
	}
	s.State = "accepted"
	s.lastActivity.Store(time.Now().UnixNano())
	if err := r.persist(s); err != nil {
		s.State = "waiting"
		_ = r.root.Remove(id + ".part")
		return err
	}
	return nil
}

func (r *Receiver) upload(w http.ResponseWriter, req *http.Request) {
	started := time.Now()
	s := r.authorized(w, req)
	if s == nil {
		return
	}
	s.uploadMu.Lock()
	if s.uploadCancel != nil {
		s.uploadMu.Unlock()
		fail(w, 429, "another block is active")
		return
	}
	uploadCtx, stopUpload := context.WithCancel(s.ctx)
	s.uploadCancel = stopUpload
	if time.Since(time.Unix(0, s.lastActivity.Load())) > 5*time.Second {
		s.throughput.reset()
	}
	s.uploading.Store(true)
	s.uploadMu.Unlock()
	defer func() {
		s.uploadMu.Lock()
		s.uploadCancel = nil
		s.lastActivity.Store(time.Now().UnixNano())
		s.uploading.Store(false)
		s.uploadMu.Unlock()
		stopUpload()
	}()
	// Pause and cancellation interrupt a stalled body/pacer without waiting for s.mu.
	readCancelled := make(chan struct{})
	stop := context.AfterFunc(uploadCtx, func() {
		defer close(readCancelled)
		// Closing a server request Body alone may wait for a blocked Read.
		// Interrupt the socket read first so local cancellation remains prompt.
		_ = http.NewResponseController(w).SetReadDeadline(time.Now())
		_ = req.Body.Close()
	})
	defer func() {
		if !stop() {
			<-readCancelled
		}
		_ = http.NewResponseController(w).SetReadDeadline(time.Time{})
	}()
	if r.cfg.UploadGate != nil {
		// Reserve this session's upload slot before queuing: at most one
		// request per admitted file may wait. Competing senders wait for the
		// device upload slot instead of exhausting no-progress retries on 429.
		// Keep the wait short: HTTP/1 may not notice a disconnected sender until
		// its unread request body is consumed, so it must not retain this slot.
		queueDeadline := time.NewTimer(time.Second)
		defer queueDeadline.Stop()
		select {
		case r.cfg.UploadGate <- struct{}{}:
			defer func() { <-r.cfg.UploadGate }()
		case <-uploadCtx.Done():
			fail(w, 409, "file upload interrupted")
			return
		case <-req.Context().Done():
			return
		case <-queueDeadline.C:
			fail(w, 429, "upload queue wait exceeded")
			return
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pauseRequested.Load() || (s.State != "accepted" && s.State != "receiving") {
		fail(w, 409, "file has not been accepted or is terminal")
		return
	}
	offset, err := strconv.ParseInt(req.Header.Get("X-File-Offset"), 10, 64)
	if err != nil || offset != s.Offset {
		fail(w, 409, "offset mismatch; query persisted offset before retry")
		return
	}
	n := req.ContentLength
	maxBlock := s.MaxBlock
	if r.cfg.Durable {
		maxBlock = r.visible(s).MaxBlock
	}
	if r.cfg.Durable && n > int64(maxBlock) {
		fail(w, 409, "receive budget changed; query current block limit")
		return
	}
	if n <= 0 || n > int64(maxBlock) || n > s.Size-s.Offset {
		fail(w, 400, "invalid block length")
		return
	}
	f, err := r.root.OpenFile(s.ID+".part", os.O_WRONLY, 0)
	if err != nil {
		fail(w, 500, "cannot open inbox file")
		return
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		fail(w, 500, "cannot seek inbox file")
		return
	}
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	stopCancel := context.AfterFunc(uploadCtx, cancel)
	defer stopCancel()
	buf := make([]byte, paceChunk)
	remaining := n
	for remaining > 0 {
		if !r.cfg.Allowed() {
			err = errors.New("authorization revoked")
			break
		}
		if err = r.pacer.Wait(ctx, int(min(remaining, paceChunk))); err != nil {
			break
		}
		if r.cfg.RouteBudget != nil {
			if p := r.cfg.RouteBudget(); p != nil {
				if err = p.Wait(ctx, int(min(remaining, paceChunk))); err != nil {
					break
				}
			}
		}
		var count int
		count, err = io.ReadFull(req.Body, buf[:min(remaining, paceChunk)])
		if err != nil {
			break
		}
		if _, err = f.Write(buf[:count]); err != nil {
			break
		}
		remaining -= int64(count)
		now := time.Now()
		s.lastActivity.Store(now.UnixNano())
		if rate, sample := s.throughput.add(now, int64(count)); sample {
			view := s.Transfer
			view.State, view.RateBps = "receiving", rate
			view.RemainingSeconds = max(int64(0), s.Size-s.Offset-n+remaining+rate-1) / rate
			s.snapshot.Store(&view)
		}
	}
	if err == nil {
		err = f.Sync()
	}
	if err != nil {
		// An interrupted block is never acknowledged. Next PUT overwrites it.
		_ = f.Truncate(offset)
		s.throughput.reset()
		s.RateBps, s.RemainingSeconds = 0, 0
		s.publish()
		fail(w, 500, "block not persisted; query offset before retry")
		return
	}
	s.Offset += n
	if rate := s.throughput.current(); rate > 0 {
		s.RateBps = rate
		s.RemainingSeconds = (s.Size - s.Offset + rate - 1) / rate
	} else if seconds := time.Since(started).Seconds(); seconds > 0 {
		s.RateBps = int64(float64(n) / seconds)
		if s.RateBps > 0 {
			s.RemainingSeconds = (s.Size - s.Offset + s.RateBps - 1) / s.RateBps
		}
	}
	s.State = "receiving"
	if err := r.persist(s); err != nil {
		s.Offset = offset
		_ = f.Truncate(offset)
		fail(w, 500, "cannot persist offset")
		return
	}
	jsonOut(w, 200, r.visible(s))
}

func (r *Receiver) commit(w http.ResponseWriter, req *http.Request) {
	s := r.authorized(w, req)
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.State == "completed" {
		if err := r.persist(s); err != nil {
			fail(w, 500, "cannot persist receipt")
			return
		}
		jsonOut(w, 200, s.Transfer)
		return
	}
	if (s.State != "receiving" && s.State != "accepted") || s.Offset != s.Size {
		fail(w, 409, "file is incomplete")
		return
	}
	f, err := r.root.Open(s.ID + ".part")
	if err != nil {
		fail(w, 500, "cannot open inbox file")
		return
	}
	verifying := s.Transfer
	verifying.State = "verifying"
	verifying.RateBps = 0
	verifying.RemainingSeconds = 0
	s.snapshot.Store(&verifying)
	defer func() {
		if s.State == "receiving" || s.State == "accepted" {
			s.publish()
		}
	}()
	h := sha256.New()
	_, err = io.Copy(h, &contextReader{ctx: s.ctx, r: f})
	_ = f.Close()
	if err != nil {
		fail(w, 500, "cannot verify inbox file")
		return
	}
	if hex.EncodeToString(h.Sum(nil)) != s.SHA256 {
		s.State = "failed"
		s.StopReason = "receiver_failed"
		s.cancel()
		_ = r.root.Remove(s.ID + ".part")
		_ = r.persist(s)
		fail(w, 422, "file checksum mismatch")
		return
	}
	// A random output name avoids remote filename, overwrite and extension execution risks.
	name := s.ID + ".received"
	if r.cfg.Durable {
		s.State = "committing"
		if err := r.persist(s); err != nil {
			s.State = "receiving"
			fail(w, 500, "cannot persist commit intent")
			return
		}
	}
	if err := r.root.Rename(s.ID+".part", name); err != nil {
		s.State = "receiving"
		fail(w, 500, "cannot commit inbox file")
		return
	}
	s.State, s.StoredName = "completed", name
	s.RateBps = 0
	s.RemainingSeconds = 0
	if err := r.persist(s); err != nil {
		fail(w, 500, "cannot persist receipt; query before retry")
		return
	}
	jsonOut(w, 200, s.Transfer)
}

func (r *Receiver) Cancel(id string) error {
	return r.cancelFile(id, "receiver_cancelled")
}

func (r *Receiver) cancelFile(id, reason string) error {
	s := r.find(id)
	if s == nil {
		return errors.New("unknown transfer")
	}
	s.cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.State == "completed" {
		return errors.New("completed file is retained")
	}
	if s.State == "failed" {
		return errors.New("failed file record is retained")
	}
	s.State = "cancelled"
	if s.StopReason == "" {
		s.StopReason = reason
	}
	s.RateBps = 0
	s.RemainingSeconds = 0
	if err := r.persist(s); err != nil {
		return err
	}
	err := r.root.Remove(s.ID + ".part")
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	return err
}

func (r *Receiver) cancelTransfer(w http.ResponseWriter, req *http.Request) {
	s := r.authorized(w, req)
	if s == nil {
		return
	}
	if err := r.cancelFile(s.ID, "sender_cancelled"); err != nil {
		fail(w, 409, err.Error())
		return
	}
	jsonOut(w, 200, map[string]bool{"cancelled": true})
}

// CopyCompleted exports only a verified file ID to a caller-owned writer. No
// arbitrary local path is exposed to a privileged process or remote peer.
func (r *Receiver) CopyCompleted(ctx context.Context, id string, dst io.Writer) error {
	s := r.find(id)
	if s == nil {
		return errors.New("unknown transfer")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.State != "completed" {
		return errors.New("file has not completed verification")
	}
	f, err := r.root.Open(s.StoredName)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(dst, h), io.LimitReader(&contextReader{ctx: ctx, r: f}, s.Size+1))
	if err != nil {
		return err
	}
	if n != s.Size || hex.EncodeToString(h.Sum(nil)) != s.SHA256 {
		return errors.New("saved file checksum mismatch")
	}
	return nil
}

// Close follows http.Server.Close, cancels incomplete tasks, then closes the
// inbox root. Completed files survive; does not recover tasks after restart.
func (r *Receiver) Stop() {
	r.cancel()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	for _, s := range r.sessions {
		s.cancel()
		s.mu.Lock()
		if s.State != "completed" && !r.cfg.Durable {
			s.State = "cancelled"
			s.publish()
			_ = r.root.Remove(s.ID + ".part")
		}
		s.mu.Unlock()
	}
}

func (r *Receiver) Close() error {
	r.Stop()
	r.closeOnce.Do(func() { r.closeErr = r.root.Close() })
	return r.closeErr
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(b)
}

func Address(ip netip.Addr, port int) (string, error) {
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" || port < 1 || port > 65535 {
		return "", fmt.Errorf("an exact mesh IP and port are required")
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
}
