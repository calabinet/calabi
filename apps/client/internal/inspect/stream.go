// stream.go — live HTTP capture: parse req/resp pairs as bytes arrive,
// instead of buffering the whole conn and parsing once at close.
//
// The old design (see inspect.go HTTPTap.Parse + cmd/calabi/inspector.go)
// held the request and response byte streams in two 256 KB CapBuffers
// for the full lifetime of the connection, then ran http.ReadRequest /
// http.ReadResponse against the accumulated bytes during End. That's
// fine for short HTTP/1.0 style "one request per conn" but broken for
// HTTP/1.1 keep-alive: the browser holds the conn idle for its full
// keep-alive timeout (~120 s on Chrome/Edge/Firefox) AFTER the response
// has arrived, so the user sees "request appears 2 minutes after I
// clicked the link" — useless for live debugging.
//
// New flow:
//
//   pumpTCP                       parser goroutine            HTTPLog
//   --------                      ----------------            -------
//   Tee(visitor→local)──Write──▶  PipeBuf.Read───▶
//                                  http.ReadRequest─┐
//   Tee(local→visitor)──Write──▶  PipeBuf.Read     │
//                                  http.ReadResponse│
//                                                   └──▶ append capture
//   On conn close: PipeBuf.Close → parser sees EOF, exits.
//
// PipeBuf is a bounded blocking-reader / non-blocking-writer pipe so the
// data plane is never throttled by the parser (writes drop on overflow,
// flagged so captures get an "overflowed" annotation).

package inspect

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// PipeBuf is a per-direction streaming pipe between the Tee writer in
// pumpTCP (non-blocking producer) and the HTTP parser goroutine
// (blocking consumer).
//
// Memory: capped at capBytes (typically 256 KB matching the old
// CapBuffer). Excess Write bytes are dropped and the dropped flag is
// set; the parser later surfaces this in the capture's Error field.
//
// Concurrency: any number of writers and one reader (the parser
// goroutine). Reads block on the cond var until either bytes arrive
// or Close is called.
type PipeBuf struct {
	mu       sync.Mutex
	cond     *sync.Cond
	buf      bytes.Buffer
	capBytes int
	closed   bool
	dropped  bool
}

// NewPipeBuf returns a PipeBuf capped at capBytes. capBytes <= 0
// falls back to 256 KB.
func NewPipeBuf(capBytes int) *PipeBuf {
	if capBytes <= 0 {
		capBytes = 256 * 1024
	}
	p := &PipeBuf{capBytes: capBytes}
	p.cond = sync.NewCond(&p.mu)
	return p
}

// Write implements io.Writer. Never returns an error. Bytes past the
// cap are dropped (flag set, parser can read it via Dropped).
//
// Returns len(b) even when bytes are dropped because Tee/io.Copy would
// otherwise treat a short write as failure and tear down the data path
// — we explicitly do NOT want capture-buffer pressure to break the
// actual proxy.
func (p *PipeBuf) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	p.mu.Lock()
	remain := p.capBytes - p.buf.Len()
	switch {
	case remain <= 0:
		p.dropped = true
	case len(b) > remain:
		p.buf.Write(b[:remain])
		p.dropped = true
		p.cond.Broadcast()
	default:
		p.buf.Write(b)
		p.cond.Broadcast()
	}
	p.mu.Unlock()
	return len(b), nil
}

// Read implements io.Reader. Blocks until data is available or the
// pipe is closed. When closed AND drained, returns 0, io.EOF.
func (p *PipeBuf) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	p.mu.Lock()
	for p.buf.Len() == 0 && !p.closed {
		p.cond.Wait()
	}
	if p.buf.Len() == 0 {
		p.mu.Unlock()
		return 0, io.EOF
	}
	n, _ := p.buf.Read(b)
	p.mu.Unlock()
	return n, nil
}

// Close marks the pipe closed. After Close, blocked Readers wake up
// and drain any remaining buffer, then see io.EOF on the next Read.
// Safe to call multiple times.
func (p *PipeBuf) Close() error {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		p.cond.Broadcast()
	}
	p.mu.Unlock()
	return nil
}

// Dropped reports whether any bytes were truncated.
func (p *PipeBuf) Dropped() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.dropped
}

// StreamParse starts a goroutine that reads request bytes from req and
// response bytes from resp, parsing pipelined HTTP/1.1 req/resp pairs
// and appending each completed pair to the log as soon as it parses.
//
// Returns a channel that closes when the parser goroutine exits (either
// because both pipes hit EOF, or because parsing failed irrecoverably).
// Callers may ignore it; the parser cleans up after itself.
//
// startedAt is the connection's open time, used as a fallback when a
// capture's own per-request start can't be measured (shouldn't happen
// in practice, but defensive).
func (t *HTTPTap) StreamParse(req, resp io.Reader, connStart time.Time) <-chan struct{} {
	done := make(chan struct{})
	if t == nil || t.log == nil {
		close(done)
		return done
	}
	go func() {
		defer close(done)
		reqReader := bufio.NewReaderSize(req, 4096)
		respReader := bufio.NewReaderSize(resp, 4096)

		for {
			// Block until enough request bytes arrive (or pipe closes
			// → io.EOF → break).
			httpReq, err := http.ReadRequest(reqReader)
			if err != nil {
				return
			}
			reqStart := time.Now()
			reqBody, _ := io.ReadAll(io.LimitReader(httpReq.Body, int64(t.log.bodyMax)))
			// Drain any remainder so the bufio reader is positioned at
			// the next request rather than mid-body — without this, a
			// POST larger than bodyMax breaks pipeline parsing for
			// every subsequent request on the same conn.
			_, _ = io.Copy(io.Discard, httpReq.Body)
			_ = httpReq.Body.Close()

			cap := &HTTPCapture{
				ID:             atomic.AddUint64(&t.log.nextID, 1),
				ProxyID:        t.proxyID,
				StartedAt:      reqStart.UTC().Format(time.RFC3339Nano),
				Method:         httpReq.Method,
				Path:           httpReq.URL.RequestURI(),
				Host:           httpReq.Host,
				RequestHeaders: flattenHeaders(httpReq.Header),
				RequestBody:    string(reqBody),
			}

			// Match the response. http.ReadResponse needs the request
			// to handle HEAD specially (no body even on 200).
			httpResp, perr := http.ReadResponse(respReader, httpReq)
			if perr != nil {
				cap.Error = "response parse: " + perr.Error()
				appendCapWithDropFlag(t.log, cap, req, resp)
				return
			}
			respBody, _ := io.ReadAll(io.LimitReader(httpResp.Body, int64(t.log.bodyMax)))
			_, _ = io.Copy(io.Discard, httpResp.Body)
			_ = httpResp.Body.Close()

			cap.ResponseStatus = httpResp.StatusCode
			cap.ResponseHeaders = flattenHeaders(httpResp.Header)
			cap.ResponseBody = string(respBody)
			cap.DurationMs = time.Since(reqStart).Milliseconds()

			appendCapWithDropFlag(t.log, cap, req, resp)
		}
	}()
	return done
}

// appendCapWithDropFlag checks both pipes for overflow and annotates
// the capture before appending. Centralized so the two append points
// in StreamParse don't drift.
func appendCapWithDropFlag(log *HTTPLog, cap *HTTPCapture, req, resp io.Reader) {
	dropped := false
	if d, ok := req.(interface{ Dropped() bool }); ok && d.Dropped() {
		dropped = true
	}
	if d, ok := resp.(interface{ Dropped() bool }); ok && d.Dropped() {
		dropped = true
	}
	if dropped {
		note := "capture buffer overflowed; body may be truncated"
		if cap.Error == "" {
			cap.Error = note
		} else {
			cap.Error += "; " + note
		}
	}
	log.append(cap)
}
