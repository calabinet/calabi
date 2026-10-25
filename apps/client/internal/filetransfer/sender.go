package filetransfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type Sender struct {
	client     *http.Client
	control    *http.Client
	base       string
	pacer      *Pacer
	allowed    func() bool
	active     chan struct{}
	probePath  func() string
	flow       *Pacer
	pathBudget func() *Pacer
	flowActive atomic.Bool
}

// NewSender deliberately uses a plain net.Dialer bound to the mesh address.
// hostnet.Dialer protects Android sockets from the VPN and must NOT be used.
func NewSender(identity *Identity, local netip.Addr, peer Peer, port int, pacer *Pacer, allowed func() bool) (*Sender, error) {
	if err := peer.Validate(); err != nil {
		return nil, err
	}
	addr, err := Address(peer.IP, port)
	if err != nil {
		return nil, err
	}
	if !local.IsValid() || local.IsUnspecified() || pacer == nil || allowed == nil {
		return nil, errors.New("local mesh IP, shared pacer and current authorization callback required")
	}
	newClient := func() *http.Client {
		dialer := &net.Dialer{Timeout: 10 * time.Second, LocalAddr: &net.TCPAddr{IP: net.IP(local.AsSlice())}}
		transport := &http.Transport{
			Proxy: nil, DialContext: dialer.DialContext, TLSClientConfig: identity.ClientTLS(peer),
			TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 90 * time.Second,
			MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, IdleConnTimeout: 30 * time.Second,
			WriteBufferSize: paceChunk, ReadBufferSize: paceChunk, ForceAttemptHTTP2: false,
		}
		return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("file redirects are forbidden") }}
	}
	return &Sender{client: newClient(), control: newClient(), base: "https://" + addr + "/file/p0", pacer: pacer, allowed: allowed, active: make(chan struct{}, 1)}, nil
}

func (s *Sender) Close() { s.client.CloseIdleConnections(); s.control.CloseIdleConnections() }

type requestError struct{ status int }

func (e *requestError) Error() string { return fmt.Sprintf("file peer returned HTTP %d", e.status) }

func (s *Sender) request(ctx context.Context, client *http.Client, method, path, token string, body io.Reader, length int64, offset int64, out any) error {
	if !s.allowed() {
		return errors.New("file transfer is no longer authorized")
	}
	req, err := http.NewRequestWithContext(ctx, method, s.base+path, body)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	// A header keeps old receivers' strict offer JSON decoder compatible.
	// Only receivers that observed this opt-in expose recipient pause.
	req.Header.Set("X-Calabi-File-Control", "pause-v1")
	if method == http.MethodPut {
		req.ContentLength = length
		req.Header.Set("X-File-Offset", strconv.FormatInt(offset, 10))
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return &requestError{resp.StatusCode}
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(out)
	}
	_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 8192))
	return err
}

// Send hashes and streams an already-opened caller-owned file. It never accepts
// a local path. The source must support seeking for offset recovery. Progress
// reports only receiver-persisted offsets, never socket-buffered bytes.
func (s *Sender) Send(ctx context.Context, src io.ReadSeeker, name string, size int64, progress func(Transfer)) (result Transfer, err error) {
	select {
	case s.active <- struct{}{}:
		defer func() { <-s.active }()
	default:
		return result, errors.New("another file send is active")
	}
	if !validName(name) || size < 0 || size == int64(^uint64(0)>>1) {
		return result, errors.New("invalid file metadata")
	}
	if _, err = src.Seek(0, io.SeekStart); err != nil {
		return result, errors.New("source does not support seeking")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(&contextReader{ctx: ctx, r: src}, size+1))
	if err != nil {
		return result, err
	}
	if n != size {
		return result, errors.New("source size changed or is unknown")
	}
	if _, err = src.Seek(0, io.SeekStart); err != nil {
		return result, err
	}
	body, _ := json.Marshal(Offer{Name: name, Size: size, SHA256: hex.EncodeToString(h.Sum(nil))})
	var offer offerReply
	if err = s.request(ctx, s.client, "POST", "/offers", "", bytes.NewReader(body), 0, 0, &offer); err != nil {
		return result, err
	}
	path := "/transfers/" + offer.ID
	if len(offer.ID) != 64 || len(offer.Token) != 64 || offer.MaxBlock < paceChunk || offer.MaxBlock > BlockSize || offer.Kbps < 1 || offer.Kbps > MaxKbps {
		return result, errors.New("invalid peer offer response")
	}
	if _, decodeErr := hex.DecodeString(offer.ID); decodeErr != nil || offer.Size != size || offer.Name != name || offer.SHA256 != hex.EncodeToString(h.Sum(nil)) {
		return result, errors.New("peer offer metadata does not match the source")
	}
	// Best-effort cancellation uses a short independent context even when the
	// caller has cancelled. Successful completion is retained by the receiver.
	defer func() {
		if err != nil {
			cancelCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = s.request(cancelCtx, s.control, "DELETE", path, offer.Token, nil, 0, 0, nil)
		}
	}()
	result = offer.Transfer
	s.pacer.cap(offer.Kbps)
	for result.State == "waiting" {
		if progress != nil {
			progress(result)
		}
		if err = wait(ctx, time.Second); err != nil {
			return result, err
		}
		if err = s.request(ctx, s.control, "GET", path, offer.Token, nil, 0, 0, &result); err != nil {
			return result, err
		}
	}
	if result.State != "accepted" {
		return result, errors.New("receiver declined the file")
	}
	transferCtx, cancel := context.WithCancel(ctx)
	var probes sync.WaitGroup
	probes.Add(1)
	go func() { defer probes.Done(); s.probe(transferCtx) }()
	defer func() { cancel(); probes.Wait() }()
	block := make([]byte, min(offer.MaxBlock, max(paceChunk, s.pacer.Kbps()*128)))
	stalled := 0
	for result.Offset < size {
		if result.Offset < 0 || result.Offset > size {
			return result, errors.New("invalid receiver offset")
		}
		if _, err = src.Seek(result.Offset, io.SeekStart); err != nil {
			return result, err
		}
		// Shrink the next block after congestion lowers the rate. Keeping the
		// original block size could turn a low-rate retry into a read timeout.
		n := int(min(int64(len(block)), size-result.Offset, int64(max(paceChunk, s.pacer.Kbps()*128))))
		if _, err = io.ReadFull(&contextReader{ctx: ctx, r: src}, block[:n]); err != nil {
			return result, errors.New("source changed or became unavailable")
		}
		start := result.Offset
		var updated Transfer
		err = s.request(ctx, s.client, "PUT", path, offer.Token, &pacedReader{allowed: s.allowed, ctx: ctx, src: bytes.NewReader(bytes.Clone(block[:n])), pacer: s.pacer}, int64(n), start, &updated)
		if err != nil {
			var httpErr *requestError
			if ctx.Err() != nil || (errors.As(err, &httpErr) && httpErr.status != 409 && httpErr.status < 500) {
				return result, err
			}
			s.pacer.Observe(0, true)
			// The write may have committed even if its response was lost. Never
			// infer the persisted offset from a client-side write count.
			for retry := 0; retry < 3; retry++ {
				if err = wait(ctx, time.Duration(retry+1)*time.Second); err != nil {
					return result, err
				}
				err = s.request(ctx, s.control, "GET", path, offer.Token, nil, 0, 0, &updated)
				if err == nil {
					break
				}
			}
			if err != nil {
				return result, err
			}
		}
		if updated.Offset != start && updated.Offset != start+int64(n) {
			return result, errors.New("receiver returned unexpected offset")
		}
		if updated.State != "accepted" && updated.State != "receiving" {
			return result, errors.New("receiver stopped the transfer")
		}
		result = updated
		if progress != nil {
			progress(result)
		}
		// An interrupted block keeps the previous persisted offset; resend it
		// after querying, rather than treating socket writes as acknowledged.
		if result.Offset == start {
			stalled++
			if stalled >= 3 {
				return result, errors.New("file transfer made no progress after three retries")
			}
			if waitErr := wait(ctx, time.Second); waitErr != nil {
				return result, waitErr
			}
		} else {
			stalled = 0
		}
	}
	for retry := 0; retry < 3; retry++ {
		err = s.request(ctx, s.client, "POST", path+"/commit", offer.Token, nil, 0, 0, &result)
		if err == nil {
			break
		}
		var httpErr *requestError
		if ctx.Err() != nil || (errors.As(err, &httpErr) && httpErr.status < 500) {
			return result, err
		}
		if waitErr := wait(ctx, time.Second); waitErr != nil {
			return result, waitErr
		}
	}
	if err != nil {
		return result, err
	}
	if result.State != "completed" || result.Offset != size || result.SHA256 != hex.EncodeToString(h.Sum(nil)) {
		return result, errors.New("missing verified completion receipt")
	}
	if progress != nil {
		progress(result)
	}
	return result, nil
}

func wait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (s *Sender) probe(ctx context.Context) {
	lastPath := ""
	for ctx.Err() == nil {
		if s.probePath != nil {
			path := s.probePath()
			if path != "" && path != lastPath {
				s.feedbackPacer().ResetProbe()
				lastPath = path
			}
		}
		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		active := s.flowActive.Load()
		start := time.Now()
		err := s.request(pctx, s.control, "GET", "/ping", "", nil, 0, 0, nil)
		cancel()
		if ctx.Err() != nil {
			return
		}
		// Waiting for a human to accept is not evidence that a loaded path can
		// sustain a higher rate. Start probing upward only after payload begins.
		if s.flow == nil || active && s.flowActive.Load() {
			s.feedbackPacer().Observe(time.Since(start), err != nil)
		}
		if wait(ctx, 2*time.Second) != nil {
			return
		}
	}
}

func (s *Sender) feedbackPacer() *Pacer {
	if s.flow != nil {
		return s.flow
	}
	return s.pacer
}

// Executed before each small source read. Re-resolve the route after the flow
// wait too, so a path change cannot retain a direct allowance for a whole block.
func (s *Sender) waitPath(ctx context.Context, n int) error {
	if s.pathBudget == nil {
		return nil
	}
	s.flowActive.Store(true)
	p := s.pathBudget()
	ceiling := s.pacer.Ceiling()
	if p != nil {
		ceiling = min(ceiling, p.Ceiling())
	}
	if s.flow != nil {
		s.flow.SetDeviceLimit(ceiling)
		if err := s.flow.Wait(ctx, n); err != nil {
			return err
		}
	}
	if p = s.pathBudget(); p != nil {
		return p.Wait(ctx, n)
	}
	return nil
}

type pacedReader struct {
	onRead    func(int)
	allowed   func() bool
	secondary *Pacer
	ctx       context.Context
	src       io.Reader
	pacer     *Pacer
	extraWait func(context.Context, int) error
}

func (r *pacedReader) Read(b []byte) (int, error) {
	if r.allowed != nil && !r.allowed() {
		return 0, errors.New("file authorization revoked")
	}
	chunk := min(len(b), paceChunk, max(1, r.pacer.Kbps()*128/10))
	if r.secondary != nil {
		chunk = min(chunk, max(1, r.secondary.Kbps()*128/10))
	}
	b = b[:chunk]
	if err := r.pacer.Wait(r.ctx, len(b)); err != nil {
		return 0, err
	}
	if r.secondary != nil {
		if err := r.secondary.Wait(r.ctx, len(b)); err != nil {
			return 0, err
		}
	}
	if r.allowed != nil && !r.allowed() {
		return 0, errors.New("file authorization revoked")
	}
	if r.extraWait != nil {
		if err := r.extraWait(r.ctx, len(b)); err != nil {
			return 0, err
		}
	}
	if r.allowed != nil && !r.allowed() {
		return 0, errors.New("file authorization revoked")
	}
	n, err := r.src.Read(b)
	if n > 0 && r.onRead != nil {
		r.onRead(n)
	}
	return n, err
}
