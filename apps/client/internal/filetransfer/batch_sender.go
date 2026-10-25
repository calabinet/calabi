package filetransfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"sync"
	"time"
)

const MaxBatchFiles = 32

// Source is an already authorized, caller-owned stream. Paths and URI access
// are owned by the ordinary user UI, never sent to a privileged daemon.
type Source struct {
	Reader io.ReadSeeker
	Name   string
	Size   int64
}

// BatchTicket contains secrets. Checkpoints belong only in the user's private
// state, never in UI/log responses or machine-wide metadata APIs.
type BatchTicket struct {
	ID    string       `json:"id"`
	Scope string       `json:"scope"`
	Peer  Peer         `json:"peer"`
	Files []FileTicket `json:"files"`
}
type FileTicket struct {
	Offer Offer  `json:"offer"`
	ID    string `json:"id"`
	Token string `json:"token"`
}
type BatchProgress struct {
	activity    *transferActivity
	Preparation *PreparationProgress `json:"preparation,omitempty"`
	Batch       string               `json:"batch"`
	Index       int                  `json:"index"`
	Count       int                  `json:"count"`
	Transfer    Transfer             `json:"transfer"`
}

// Preparation is local work, separate from the receiver's confirmed offset.
type PreparationProgress struct {
	Phase string `json:"phase"`
	Name  string `json:"name"`
	Index int    `json:"index"`
	Count int    `json:"count"`
	Bytes int64  `json:"bytes"`
	Size  int64  `json:"size"`
}

type hashProgressWriter struct {
	io.Writer
	bytes  int64
	last   time.Time
	report func(int64)
}

func (w *hashProgressWriter) Write(b []byte) (int, error) {
	n, err := w.Writer.Write(b)
	w.bytes += int64(n)
	if time.Since(w.last) >= 200*time.Millisecond {
		w.report(w.bytes)
		w.last = time.Now()
	}
	return n, err
}

type BatchSender struct {
	peerRate *Pacer
	*Sender
	scope string
	peer  Peer
}

type peerStoppedError struct{ Transfer Transfer }

func (e *peerStoppedError) Error() string { return "receiver stopped the batch: " + e.Transfer.State }

func NewBatchSender(identity *Identity, local netip.Addr, peer Peer, port int, pacer *Pacer, allowed func() bool, scope string) (*BatchSender, error) {
	if scope == "" {
		return nil, errors.New("identity scope required")
	}
	s, err := NewSender(identity, local, peer, port, pacer, allowed)
	if err != nil {
		return nil, err
	}
	s.base = "https://" + netJoin(peer.IP, port) + "/file/v1"
	return &BatchSender{Sender: s, scope: scope, peer: peer}, nil
}

func netJoin(ip netip.Addr, port int) string { addr, _ := Address(ip, port); return addr }

// SendBatch checkpoints before making offers and after learning their tokens.
// Network failure pauses a task; only CancelBatch revokes it. On resume sources
// must be re-authorized/reopened by the user layer, then rehashed here.
func (s *BatchSender) SendBatch(ctx context.Context, sources []Source, ticket *BatchTicket, checkpoint func(BatchTicket) error, progress func(BatchProgress)) error {
	select {
	case s.active <- struct{}{}:
		defer func() { <-s.active }()
	default:
		return errors.New("another batch send is active")
	}
	if ticket == nil || checkpoint == nil || len(sources) < 1 || len(sources) > MaxBatchFiles {
		return errors.New("1..32 files and a private checkpoint store required")
	}
	fresh := ticket.ID == ""
	s.peerRate, _ = NewPacer(MaxKbps)
	if fresh {
		*ticket = BatchTicket{ID: randomID(), Scope: s.scope, Peer: s.peer, Files: make([]FileTicket, len(sources))}
	} else if !validID(ticket.ID) || ticket.Scope != s.scope || ticket.Peer != s.peer || len(ticket.Files) != len(sources) {
		return errors.New("resume identity or source count changed")
	}
	for n, src := range sources {
		if src.Reader == nil || !validName(src.Name) || src.Size < 0 || src.Size >= 1<<60 {
			return errors.New("invalid source metadata")
		}
		if _, err := src.Reader.Seek(0, io.SeekStart); err != nil {
			return errors.New("source must be seekable; stage nonseekable documents first")
		}
		h := sha256.New()
		reportHash := func(bytes int64) {
			if progress != nil {
				progress(BatchProgress{Batch: ticket.ID, Count: len(sources), Preparation: &PreparationProgress{Phase: "hashing", Name: src.Name, Index: n, Count: len(sources), Bytes: min(bytes, src.Size), Size: src.Size}})
			}
		}
		reportHash(0)
		writer := &hashProgressWriter{Writer: h, last: time.Now(), report: reportHash}
		size, err := io.Copy(writer, io.LimitReader(&contextReader{ctx: ctx, r: src.Reader}, src.Size+1))
		if err != nil {
			return err
		}
		if size != src.Size {
			return errors.New("source size changed")
		}
		reportHash(size)
		offer := Offer{BatchCount: len(sources), Batch: ticket.ID, Name: src.Name, Size: src.Size, SHA256: hex.EncodeToString(h.Sum(nil))}
		if fresh {
			offer.ClientID = randomID()
			ticket.Files[n] = FileTicket{Offer: offer}
		} else {
			old := ticket.Files[n].Offer
			offer.ClientID = old.ClientID
			if !validID(old.ClientID) || old != offer {
				return errors.New("source changed; resume refused")
			}
		}
	}
	if err := checkpoint(*ticket); err != nil {
		return err
	}
	for n := range ticket.Files {
		ft := &ticket.Files[n]
		if progress != nil {
			progress(BatchProgress{Batch: ticket.ID, Count: len(sources), Preparation: &PreparationProgress{Phase: "connecting", Name: ft.Offer.Name, Index: n, Count: len(sources), Size: ft.Offer.Size}})
		}
		body, _ := json.Marshal(ft.Offer)
		var reply offerReply
		if err := s.retry(ctx, func() error {
			return s.request(ctx, s.client, "POST", "/offers", "", bytes.NewReader(body), 0, 0, &reply)
		}); err != nil {
			return err
		}
		if !validOfferReply(reply, ft.Offer) {
			return errors.New("invalid peer offer response")
		}
		if ft.ID != "" && (ft.ID != reply.ID || ft.Token != reply.Token) {
			return errors.New("peer lost the original transfer; start a new batch explicitly")
		}
		ft.ID, ft.Token = reply.ID, reply.Token
		s.peerRate.fixedLimit(reply.Kbps)
		if err := checkpoint(*ticket); err != nil {
			return err
		}
	}
	transferCtx, cancel := context.WithCancel(ctx)
	s.flowActive.Store(false)
	s.feedbackPacer().ResetProbe()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); s.probe(transferCtx) }()
	defer func() { cancel(); wg.Wait() }()
	for fileIndex, src := range sources {
		var meter throughput
		ft := ticket.Files[fileIndex]
		path := "/transfers/" + ft.ID
		var current Transfer
		report := func() {
			if progress != nil {
				progress(BatchProgress{Batch: ticket.ID, Index: fileIndex, Count: len(sources), Transfer: current})
			}
		}
		query := func() error {
			if err := s.request(ctx, s.control, "GET", path, ft.Token, nil, 0, 0, &current); err != nil {
				return err
			}
			if err := validateTransfer(current, ft); err != nil {
				return err
			}
			s.peerRate.fixedLimit(current.Kbps)
			return nil
		}
		if err := s.retry(ctx, query); err != nil {
			return err
		}
		ready := func() error {
			paused := current.State == "paused"
			for current.State == "waiting" || current.State == "verifying" || current.State == "committing" || current.State == "paused" {
				s.flowActive.Store(false)
				paused = paused || current.State == "paused"
				meter.reset()
				report()
				if err := wait(ctx, time.Second); err != nil {
					return err
				}
				if err := s.retry(ctx, query); err != nil {
					return err
				}
			}
			if paused && current.State != "paused" && current.State != "cancelled" && current.State != "failed" {
				s.feedbackPacer().resumeProbe()
			}
			if current.State == "cancelled" || current.State == "failed" {
				report()
				return &peerStoppedError{Transfer: current}
			}
			return nil
		}
		if err := ready(); err != nil {
			return err
		}
		if current.State == "completed" {
			report()
			continue
		}
		if current.State != "accepted" && current.State != "receiving" && current.State != "waiting_sender" {
			return errors.New("receiver rejected or cancelled a file")
		}
		stalled := 0
		report()
		block := make([]byte, BlockSize)
		for current.Offset < src.Size {
			if _, err := src.Reader.Seek(current.Offset, io.SeekStart); err != nil {
				return err
			}
			n := int(min(src.Size-current.Offset, int64(current.MaxBlock), int64(max(paceChunk, min(s.pacer.Kbps(), s.peerRate.Kbps(), s.feedbackPacer().Kbps())*128))))
			if _, err := io.ReadFull(&contextReader{ctx: ctx, r: src.Reader}, block[:n]); err != nil {
				return errors.New("source changed or became unavailable")
			}
			start := current.Offset
			var updated Transfer
			// An early response can precede the HTTP writer finishing the body.
			// Each request owns its small block until that writer releases it.
			confirmed := current
			var read int64
			activity := func(count int) {
				read += int64(count)
				now := time.Now()
				if rate, sample := meter.add(now, int64(count)); sample && progress != nil {
					remaining := max(int64(0), src.Size-start-read)
					for i := fileIndex + 1; i < len(ticket.Files); i++ {
						remaining += ticket.Files[i].Offer.Size
					}
					progress(BatchProgress{Batch: ticket.ID, Index: fileIndex, Count: len(sources), Transfer: confirmed, activity: &transferActivity{id: ft.ID, rate: rate, remaining: (remaining + rate - 1) / rate, at: now}})
				}
			}
			err := s.request(ctx, s.client, "PUT", path, ft.Token, &pacedReader{allowed: s.allowed, secondary: s.peerRate, extraWait: s.waitPath, onRead: activity, ctx: ctx, src: bytes.NewReader(bytes.Clone(block[:n])), pacer: s.pacer}, int64(n), start, &updated)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				// A cancelled/paused upload may fail before returning a receipt.
				// Read the authenticated state instead of guessing from HTTP status.
				original := err
				if err := s.retry(ctx, query); err != nil {
					s.feedbackPacer().Observe(0, true)
					return original
				}
				// A recovered control response can follow a quick pause/resume,
				// receiver contention or a storage error. None alone establishes
				// path congestion; the independent ping probe measures that.
			} else {
				if err := validateTransfer(updated, ft); err != nil {
					return err
				}
				current = updated
				s.peerRate.fixedLimit(current.Kbps)
			}
			if err := ready(); err != nil {
				return err
			}
			if current.Offset != start && current.Offset != start+int64(n) {
				return errors.New("unexpected persisted offset")
			}
			if current.State != "accepted" && current.State != "receiving" && current.State != "waiting_sender" {
				return errors.New("receiver stopped the file")
			}
			report()
			if current.Offset == start {
				stalled++
				if stalled >= 3 {
					return errors.New("upload paused after three attempts without progress")
				}
				if err := wait(ctx, time.Second); err != nil {
					return err
				}
			} else {
				stalled = 0
			}
		}
		if err := s.retry(ctx, func() error {
			err := s.request(ctx, s.client, "POST", path+"/commit", ft.Token, nil, 0, 0, &current)
			if err != nil && ctx.Err() == nil {
				if queryErr := query(); queryErr == nil {
					if readyErr := ready(); readyErr != nil {
						return readyErr
					}
					if current.State == "completed" {
						return nil
					}
				}
			}
			return err
		}); err != nil {
			return err
		}
		if err := validateTransfer(current, ft); err != nil {
			return err
		}
		if current.State != "completed" || current.Offset != src.Size {
			return errors.New("missing verified completion receipt")
		}
		report()
	}
	return nil
}

func validateTransfer(t Transfer, ft FileTicket) error {
	if t.Kbps < 1 || t.Kbps > MaxKbps {
		return errors.New("invalid receive rate ceiling")
	}
	if t.ID != ft.ID || t.BatchCount != ft.Offer.BatchCount || t.ClientID != ft.Offer.ClientID || t.Batch != ft.Offer.Batch || t.Name != ft.Offer.Name || t.Size != ft.Offer.Size || t.SHA256 != ft.Offer.SHA256 || t.Offset < 0 || t.Offset > t.Size || t.Kbps < 1 || t.Kbps > MaxKbps || t.MaxBlock < paceChunk || t.MaxBlock > BlockSize {
		return errors.New("invalid receiver transfer state")
	}
	if t.State == "completed" && t.Offset != t.Size {
		return errors.New("invalid completed offset")
	}
	return nil
}
func retryable(err error) bool {
	var stopped *peerStoppedError
	if errors.As(err, &stopped) {
		return false
	}
	var e *requestError
	return !errors.As(err, &e) || e.status == 409 || e.status == 429 || e.status >= 500
}
func (s *BatchSender) retry(ctx context.Context, call func() error) error {
	var err error
	for n := 0; n < 3; n++ {
		err = call()
		if err == nil || !retryable(err) || ctx.Err() != nil {
			return err
		}
		if n < 2 {
			if err := wait(ctx, time.Duration(n+1)*time.Second); err != nil {
				return err
			}
		}
	}
	return err
}
func validOfferReply(reply offerReply, offer Offer) bool {
	return validID(reply.ID) && validID(reply.Token) && reply.BatchCount == offer.BatchCount && reply.ClientID == offer.ClientID && reply.Batch == offer.Batch && reply.Name == offer.Name && reply.Size == offer.Size && reply.SHA256 == offer.SHA256 && reply.Kbps >= 1 && reply.Kbps <= MaxKbps && reply.MaxBlock >= paceChunk && reply.MaxBlock <= BlockSize
}

func (s *BatchSender) CancelBatch(ctx context.Context, ticket BatchTicket) error {
	ticket.Files = append([]FileTicket(nil), ticket.Files...)
	return s.cancelBatch(ctx, &ticket, nil)
}

func (s *BatchSender) cancelBatch(ctx context.Context, ticket *BatchTicket, checkpoint func(BatchTicket) error) error {
	if ticket.Scope != s.scope || ticket.Peer != s.peer {
		return errors.New("cancel identity changed")
	}
	var all []error
	for n, f := range ticket.Files {
		original := f
		if f.ID == "" && validID(f.Offer.ClientID) {
			// Recover an offer whose reply was lost before the private checkpoint.
			// ClientID makes this idempotent; validate the full offer before using it.
			body, _ := json.Marshal(f.Offer)
			var reply offerReply
			err := s.request(ctx, s.control, "POST", "/offers", "", bytes.NewReader(body), 0, 0, &reply)
			if err != nil {
				all = append(all, err)
				continue
			}
			if !validOfferReply(reply, f.Offer) {
				all = append(all, errors.New("invalid peer offer response"))
				continue
			}
			f.ID, f.Token = reply.ID, reply.Token
			ticket.Files[n] = f
			if checkpoint != nil {
				if err := checkpoint(*ticket); err != nil {
					ticket.Files[n] = original
					all = append(all, err)
					continue
				}
			}
		}
		if f.ID == "" {
			continue
		}
		if !validID(f.ID) || !validID(f.Token) {
			return errors.New("invalid transfer ticket")
		}
		err := s.request(ctx, s.control, "DELETE", "/transfers/"+f.ID, f.Token, nil, 0, 0, nil)
		var peerErr *requestError
		if errors.As(err, &peerErr) {
			if peerErr.status == 404 || peerErr.status == 410 {
				continue
			}
			if peerErr.status == 409 {
				var current Transfer
				if queryErr := s.request(ctx, s.control, "GET", "/transfers/"+f.ID, f.Token, nil, 0, 0, &current); queryErr == nil && validateTransfer(current, f) == nil && (current.State == "completed" || current.State == "cancelled" || current.State == "failed") {
					continue
				}
			}
		}
		if err != nil {
			all = append(all, err)
		}
	}
	return errors.Join(all...)
}
