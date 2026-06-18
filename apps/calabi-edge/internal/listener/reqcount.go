package listener

import (
	"bytes"
	"io"
	"strconv"
)

// reqcount.go — true per-REQUEST HTTP/1.1 counting for the per-day request
// quota (daily_http_reqs, 2026-06-12).
//
// The edge proxies HTTP/HTTPS by sniffing the FIRST request's head (for
// routing) and then byte-copying the rest of the connection transparently
// (http.go / https.go). To enforce a per-request cap we must see every
// request on a keepalive connection — so this wraps the client→server byte
// stream and parses just enough HTTP/1.1 framing to find request boundaries.
//
// Safety contract: the wrapper NEVER mutates bytes (every byte read from the
// source is returned verbatim), and on ANY framing ambiguity it FAILS OPEN —
// it transitions to passthrough and stops counting. A parser bug can only
// under-count; it can never corrupt the proxied stream or wrongly block a
// connection. Chunked request bodies and protocol upgrades (websockets) also
// fail open, since parsing those byte-exactly isn't worth the risk for a
// free-tier abuse guard.

type rcState int

const (
	rcBody rcState = iota // skipping a Content-Length body (bodyLeft bytes left)
	rcHead                // accumulating a request header block (→ blank line)
	rcPass                // gave up / upgraded → transparent passthrough, no counting
)

// rcMaxHead bounds a single request's header block before we fail open, same
// ceiling sniffHTTP uses for request #1.
const rcMaxHead = 16 * 1024

// requestCounter is the per-connection request-boundary parser. onRequest is
// invoked once per request detected AFTER the first (request #1 is counted by
// the caller from the sniffed head). When onRequest returns an error (daily
// cap spent) it is stored in abort and surfaced by the wrapping reader so the
// listener tears the connection down.
type requestCounter struct {
	onRequest func() error

	st       rcState
	bodyLeft int64
	head     bytes.Buffer
	abort    error
}

// newRequestCounter primes a counter to begin AFTER request #1's head. The
// bytes that follow on the wire are request #1's body (if any), so we seed the
// state from request #1's framing to find request #2 correctly.
func newRequestCounter(firstHead []byte, onRequest func() error) *requestCounter {
	rc := &requestCounter{onRequest: onRequest}
	rc.st, rc.bodyLeft = nextStateFor(firstHead)
	return rc
}

// wrap returns an io.Reader that forwards src verbatim while counting.
func (rc *requestCounter) wrap(src io.Reader) io.Reader {
	return &countingReader{rc: rc, src: src}
}

type countingReader struct {
	rc  *requestCounter
	src io.Reader
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.rc.abort != nil {
		return 0, c.rc.abort
	}
	n, err := c.src.Read(p)
	if n > 0 {
		c.rc.feed(p[:n])
	}
	// If a request in this chunk tripped the cap, forward this chunk's bytes
	// (n) but signal the abort so io.Copy unwinds and the conn is closed.
	if err == nil && c.rc.abort != nil {
		err = c.rc.abort
	}
	return n, err
}

// feed advances the parser over a chunk of client→server bytes.
func (rc *requestCounter) feed(data []byte) {
	for len(data) > 0 && rc.st != rcPass && rc.abort == nil {
		switch rc.st {
		case rcBody:
			data = rc.skipBody(data)
		case rcHead:
			data = rc.readHead(data)
		}
	}
}

// skipBody consumes up to bodyLeft bytes of the current request's body.
func (rc *requestCounter) skipBody(data []byte) []byte {
	if int64(len(data)) < rc.bodyLeft {
		rc.bodyLeft -= int64(len(data))
		return nil
	}
	consumed := rc.bodyLeft
	rc.bodyLeft = 0
	rc.st = rcHead
	return data[consumed:]
}

// readHead accumulates header bytes until the blank-line terminator, then
// counts the request and sets up the next body state.
func (rc *requestCounter) readHead(data []byte) []byte {
	for i := 0; i < len(data); i++ {
		rc.head.WriteByte(data[i])
		if rc.head.Len() > rcMaxHead {
			rc.st = rcPass // runaway header → fail open
			rc.head.Reset()
			return nil
		}
		if endsWithHeaderTerminator(rc.head.Bytes()) {
			head := append([]byte(nil), rc.head.Bytes()...)
			rc.head.Reset()
			rc.countRequest()
			rc.st, rc.bodyLeft = nextStateFor(head)
			return data[i+1:]
		}
	}
	return nil
}

func (rc *requestCounter) countRequest() {
	if rc.onRequest == nil {
		return
	}
	if err := rc.onRequest(); err != nil {
		rc.abort = err
	}
}

// nextStateFor maps a request's header block to the parser state for its body.
// Chunked / upgrade / ambiguous Content-Length all fail open (rcPass).
func nextStateFor(head []byte) (rcState, int64) {
	cl, chunked, upgrade := parseBodyFraming(head)
	switch {
	case upgrade, chunked, cl < 0:
		return rcPass, 0
	case cl == 0:
		return rcHead, 0
	default:
		return rcBody, cl
	}
}

// parseBodyFraming reads Content-Length / Transfer-Encoding / Upgrade from a
// request header block. contentLength == -1 signals "ambiguous → fail open".
// The request line (line 0) is skipped so a "scheme://host" path can't be
// mistaken for a header.
func parseBodyFraming(head []byte) (contentLength int64, chunked, upgrade bool) {
	lines := bytes.Split(head, []byte("\n"))
	for i, ln := range lines {
		if i == 0 {
			continue // request line
		}
		ln = bytes.TrimRight(ln, "\r")
		colon := bytes.IndexByte(ln, ':')
		if colon < 0 {
			continue
		}
		name := string(bytes.ToLower(bytes.TrimSpace(ln[:colon])))
		val := bytes.TrimSpace(ln[colon+1:])
		switch name {
		case "transfer-encoding":
			if bytes.Contains(bytes.ToLower(val), []byte("chunked")) {
				chunked = true
			}
		case "content-length":
			n, err := strconv.ParseInt(string(val), 10, 64)
			if err != nil || n < 0 {
				contentLength = -1 // ambiguous
			} else if contentLength != -1 {
				contentLength = n
			}
		case "upgrade":
			if len(val) > 0 {
				upgrade = true
			}
		}
	}
	return contentLength, chunked, upgrade
}

// endsWithHeaderTerminator reports whether b ends in a blank line (\r\n\r\n,
// or a bare \n\n some lenient clients send).
func endsWithHeaderTerminator(b []byte) bool {
	n := len(b)
	if n >= 4 && b[n-4] == '\r' && b[n-3] == '\n' && b[n-2] == '\r' && b[n-1] == '\n' {
		return true
	}
	if n >= 2 && b[n-2] == '\n' && b[n-1] == '\n' {
		return true
	}
	return false
}
