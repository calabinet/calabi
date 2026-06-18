// Package inspect captures per-connection (and per-HTTP-request) detail
// for the "请求 inspector" UI. Two ring buffers per tunnel:
//
//   - Connections: TCP-level summary. One row per accepted visitor
//     connection. Cheap (a few hundred bytes per entry), always-on.
//   - HTTPCaptures: parsed HTTP request/response pairs, body-clipped
//     at 64KB. Opt-in (the session has to wrap streams in NewHTTPTap
//     for the tunnel's data path) — bodies are user-visible so we
//     don't want to capture them unless the user asked.
//
// HTTP capture strategy: we buffer the per-connection byte streams
// (capped, so a long-lived keep-alive doesn't OOM us), then parse
// after the connection closes. Trade-off: in-flight requests don't
// appear in the UI until the conn ends, but the implementation is
// rock-solid simple and doesn't leak parser goroutines.
//
// Memory budget: 200 connections × 256 B + 100 captures × 64 KB +
// per-open-conn 256 KB capture buffer = ~6.5 MB steady-state per
// HTTP-tunnel.
package inspect

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---- per-connection log ---------------------------------------------------

// Connection is one accepted visitor connection summary.
type Connection struct {
	ID         uint64 `json:"id"`
	ProxyID    string `json:"proxy_id"`
	StartedAt  string `json:"started_at"`
	EndedAt    string `json:"ended_at,omitempty"`
	VisitorIP  string `json:"visitor_ip,omitempty"`
	BytesIn    int64  `json:"bytes_in"`
	BytesOut   int64  `json:"bytes_out"`
	DurationMs int64  `json:"duration_ms,omitempty"`
	Error      string `json:"error,omitempty"`
}

// ConnectionLog is a per-tunnel ring buffer. Zero-value is unusable;
// use NewConnectionLog. Bounded by capacity; oldest entries dropped.
type ConnectionLog struct {
	mu      sync.RWMutex
	cap     int
	entries []*Connection
	nextID  uint64
}

func NewConnectionLog(capacity int) *ConnectionLog {
	if capacity <= 0 {
		capacity = 200
	}
	return &ConnectionLog{cap: capacity, entries: make([]*Connection, 0, capacity)}
}

// Begin records a new connection. The returned *Connection is the
// caller's handle for filling in End* fields when the conn closes.
func (l *ConnectionLog) Begin(proxyID, visitorIP string) *Connection {
	id := atomic.AddUint64(&l.nextID, 1)
	c := &Connection{
		ID:        id,
		ProxyID:   proxyID,
		StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
		VisitorIP: visitorIP,
	}
	l.mu.Lock()
	if len(l.entries) >= l.cap {
		copy(l.entries, l.entries[1:])
		l.entries = l.entries[:len(l.entries)-1]
	}
	l.entries = append(l.entries, c)
	l.mu.Unlock()
	return c
}

// End fills in the close-time fields. Called on the connection
// returned by Begin (the pointer aliases the ring slot).
func (l *ConnectionLog) End(c *Connection, bytesIn, bytesOut int64, err error) {
	if c == nil {
		return
	}
	now := time.Now().UTC()
	l.mu.Lock()
	c.EndedAt = now.Format(time.RFC3339Nano)
	c.BytesIn = bytesIn
	c.BytesOut = bytesOut
	if start, perr := time.Parse(time.RFC3339Nano, c.StartedAt); perr == nil {
		c.DurationMs = now.Sub(start).Milliseconds()
	}
	if err != nil {
		c.Error = err.Error()
	}
	l.mu.Unlock()
}

// Snapshot returns the current ring contents, most recent first.
func (l *ConnectionLog) Snapshot() []Connection {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]Connection, 0, len(l.entries))
	for i := len(l.entries) - 1; i >= 0; i-- {
		out = append(out, *l.entries[i])
	}
	return out
}

// SnapshotProxy returns only entries for proxyID, most recent first.
func (l *ConnectionLog) SnapshotProxy(proxyID string) []Connection {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]Connection, 0)
	for i := len(l.entries) - 1; i >= 0; i-- {
		if l.entries[i].ProxyID == proxyID {
			out = append(out, *l.entries[i])
		}
	}
	return out
}

// ---- HTTP captures --------------------------------------------------------

// HTTPCapture is one parsed request/response pair.
type HTTPCapture struct {
	ID              uint64            `json:"id"`
	ProxyID         string            `json:"proxy_id"`
	StartedAt       string            `json:"started_at"`
	Method          string            `json:"method"`
	Path            string            `json:"path"`
	Host            string            `json:"host,omitempty"`
	RequestHeaders  map[string]string `json:"request_headers,omitempty"`
	RequestBody     string            `json:"request_body,omitempty"`
	ResponseStatus  int               `json:"response_status,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	ResponseBody    string            `json:"response_body,omitempty"`
	DurationMs      int64             `json:"duration_ms,omitempty"`
	Error           string            `json:"error,omitempty"`
}

// HTTPLog is the per-tunnel ring buffer for captured requests.
type HTTPLog struct {
	mu      sync.RWMutex
	cap     int
	entries []*HTTPCapture
	bodyMax int
	bufMax  int // total bytes per connection we buffer for parsing
	nextID  uint64
}

func NewHTTPLog(capacity, bodyMax int) *HTTPLog {
	if capacity <= 0 {
		capacity = 100
	}
	if bodyMax <= 0 {
		bodyMax = 64 * 1024
	}
	return &HTTPLog{
		cap:     capacity,
		bodyMax: bodyMax,
		bufMax:  256 * 1024,
		entries: make([]*HTTPCapture, 0, capacity),
	}
}

// BodyMax returns the per-body cap. Exposed for tests.
func (l *HTTPLog) BodyMax() int { return l.bodyMax }

// BufMax returns the per-connection capture cap.
func (l *HTTPLog) BufMax() int { return l.bufMax }

func (l *HTTPLog) append(c *HTTPCapture) {
	l.mu.Lock()
	if len(l.entries) >= l.cap {
		copy(l.entries, l.entries[1:])
		l.entries = l.entries[:len(l.entries)-1]
	}
	l.entries = append(l.entries, c)
	l.mu.Unlock()
}

// Snapshot returns the most-recent-first slice.
func (l *HTTPLog) Snapshot() []HTTPCapture {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]HTTPCapture, 0, len(l.entries))
	for i := len(l.entries) - 1; i >= 0; i-- {
		out = append(out, *l.entries[i])
	}
	return out
}

// SnapshotProxy returns only entries for proxyID.
func (l *HTTPLog) SnapshotProxy(proxyID string) []HTTPCapture {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]HTTPCapture, 0)
	for i := len(l.entries) - 1; i >= 0; i-- {
		if l.entries[i].ProxyID == proxyID {
			out = append(out, *l.entries[i])
		}
	}
	return out
}

// Get returns one capture by id, or nil.
func (l *HTTPLog) Get(id uint64) *HTTPCapture {
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, c := range l.entries {
		if c.ID == id {
			cc := *c
			return &cc
		}
	}
	return nil
}

// CapBuffer is the per-connection write-through buffer the session
// wraps both halves of the visitor↔local stream in. Read/write methods
// pass bytes through unchanged; the bounded buffer holds a copy.
//
// Usage from session.pumpTCP (per accepted connection):
//
//	reqBuf := inspect.NewCapBuffer(httpLog.BufMax())
//	respBuf := inspect.NewCapBuffer(httpLog.BufMax())
//	visIn := io.TeeReader(streamReader, reqBuf)   // visitor → local
//	localIn := io.TeeReader(localReader, respBuf) // local → visitor
//	// ... io.Copy as usual ...
//	// After both directions close:
//	tap.Parse(proxyID, reqBuf.Bytes(), respBuf.Bytes(), startedAt)
type CapBuffer struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	cap     int
	dropped bool
}

func NewCapBuffer(capBytes int) *CapBuffer {
	if capBytes <= 0 {
		capBytes = 256 * 1024
	}
	return &CapBuffer{cap: capBytes}
}

// Write implements io.Writer. Past cap, drops new bytes silently
// (the boolean flag records that truncation happened, surfaced via
// the Error field in the resulting capture).
func (b *CapBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remain := b.cap - b.buf.Len()
	if remain <= 0 {
		b.dropped = true
		return len(p), nil
	}
	if len(p) > remain {
		b.buf.Write(p[:remain])
		b.dropped = true
		return len(p), nil
	}
	b.buf.Write(p)
	return len(p), nil
}

// Bytes returns the captured slice. Snapshot — safe to read after the
// connection ends; concurrent Write while reading is allowed but
// returned bytes are a copy of the buffer at the lock moment.
func (b *CapBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]byte, b.buf.Len())
	copy(out, b.buf.Bytes())
	return out
}

// Dropped reports whether bytes were truncated.
func (b *CapBuffer) Dropped() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dropped
}

// HTTPTap pairs an HTTPLog with a proxy_id for convenient
// per-connection captures.
type HTTPTap struct {
	log     *HTTPLog
	proxyID string
}

func NewHTTPTap(log *HTTPLog, proxyID string) *HTTPTap {
	return &HTTPTap{log: log, proxyID: proxyID}
}

// Parse consumes the buffered request + response byte streams for one
// connection and appends one HTTPCapture per request/response pair.
// Designed to be called once at connection close.
func (t *HTTPTap) Parse(reqBytes, respBytes []byte, startedAt time.Time, dropped bool) {
	if t == nil || t.log == nil {
		return
	}
	if len(reqBytes) == 0 {
		return
	}
	reqReader := bufio.NewReaderSize(bytes.NewReader(reqBytes), 4096)
	respReader := bufio.NewReaderSize(bytes.NewReader(respBytes), 4096)

	// Pipelined HTTP/1.1: requests are serial, responses arrive in the
	// same order. Loop until either side stops parsing cleanly.
	for {
		req, rerr := http.ReadRequest(reqReader)
		if rerr != nil {
			return
		}
		reqBody, _ := io.ReadAll(io.LimitReader(req.Body, int64(t.log.bodyMax)))
		req.Body.Close()

		cap := &HTTPCapture{
			ID:             atomic.AddUint64(&t.log.nextID, 1),
			ProxyID:        t.proxyID,
			StartedAt:      startedAt.UTC().Format(time.RFC3339Nano),
			Method:         req.Method,
			Path:           req.URL.RequestURI(),
			Host:           req.Host,
			RequestHeaders: flattenHeaders(req.Header),
			RequestBody:    string(reqBody),
		}

		// Match a response. http.ReadResponse needs the originating
		// request to handle HEAD specially.
		resp, perr := http.ReadResponse(respReader, req)
		if perr != nil {
			cap.Error = "response parse: " + perr.Error()
			t.log.append(cap)
			return
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, int64(t.log.bodyMax)))
		resp.Body.Close()
		cap.ResponseStatus = resp.StatusCode
		cap.ResponseHeaders = flattenHeaders(resp.Header)
		cap.ResponseBody = string(respBody)
		if !startedAt.IsZero() {
			cap.DurationMs = time.Since(startedAt).Milliseconds()
		}
		if dropped {
			if cap.Error == "" {
				cap.Error = "capture buffer overflowed; body may be truncated"
			} else {
				cap.Error += "; capture buffer overflowed"
			}
		}
		t.log.append(cap)
	}
}

// flattenHeaders converts http.Header (map of slices) into a flat
// map. Multi-value headers join with ", ". Sensitive headers
// (Authorization, Cookie) are masked — the user explicitly opting
// into HTTP capture doesn't necessarily want every secret in their
// browser dev tools.
func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vs := range h {
		v := strings.Join(vs, ", ")
		if isSensitive(k) {
			v = redacted(v)
		}
		out[k] = v
	}
	return out
}

func isSensitive(k string) bool {
	switch strings.ToLower(k) {
	case "authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token":
		return true
	}
	return false
}

func redacted(v string) string {
	if len(v) <= 8 {
		return "[redacted]"
	}
	return v[:4] + "..." + v[len(v)-4:] + " [redacted]"
}

// MarshalCaptures returns the snapshot as JSON. Helper for handlers
// that don't want to import this package directly.
func MarshalCaptures(log *HTTPLog) ([]byte, error) {
	return json.Marshal(map[string]any{"items": log.Snapshot()})
}

// ---- replay --------------------------------------------------------------

// Replay re-sends a captured request to the given target URL. Returns
// the new response status + body (clipped at 64KB) and any error.
// Used by the UI's "重放" button.
func Replay(ctx context.Context, target string, cap HTTPCapture) (int, []byte, error) {
	u := strings.TrimRight(target, "/") + cap.Path
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		u = "http://" + u
	}
	req, err := http.NewRequestWithContext(ctx, cap.Method, u,
		bytes.NewReader([]byte(cap.RequestBody)))
	if err != nil {
		return 0, nil, err
	}
	for k, v := range cap.RequestHeaders {
		switch strings.ToLower(k) {
		case "content-length", "host", "connection", "transfer-encoding":
			continue
		}
		if isSensitive(k) {
			continue // can't replay redacted credentials
		}
		req.Header.Set(k, v)
	}
	if cap.Host != "" {
		req.Host = cap.Host
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return resp.StatusCode, body, nil
}
