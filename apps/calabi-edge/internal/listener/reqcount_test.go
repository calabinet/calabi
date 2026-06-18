package listener

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// oneByteReader hands out one byte per Read so tests exercise the parser's
// cross-Read state machine (heads split across reads, etc.).
type oneByteReader struct {
	data []byte
	pos  int
}

func (r *oneByteReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = r.data[r.pos]
	r.pos++
	return 1, nil
}

// drainCount runs `rest` through a counter primed on firstHead and returns the
// forwarded bytes + the number of requests counted (beyond #1).
func drainCount(t *testing.T, firstHead, rest []byte, src io.Reader) (forwarded []byte, count int) {
	t.Helper()
	rc := newRequestCounter(firstHead, func() error { count++; return nil })
	var out bytes.Buffer
	if _, err := io.Copy(&out, rc.wrap(src)); err != nil {
		t.Fatalf("copy: %v", err)
	}
	return out.Bytes(), count
}

func TestRequestCounter_CountsPipelinedAndSkipsBodies(t *testing.T) {
	first := []byte("GET /a HTTP/1.1\r\nHost: x\r\n\r\n") // no body
	// req#2 has a Content-Length body that CONTAINS a fake request line — it
	// must be skipped, not counted. req#3 is a plain GET.
	body := "GET /evil HTTP/1.1\r\nHost: y\r\n\r\n" // 30 bytes, lives inside req#2 body
	req2 := "POST /b HTTP/1.1\r\nHost: x\r\nContent-Length: " +
		itoaTest(len(body)) + "\r\n\r\n" + body
	req3 := "GET /c HTTP/1.1\r\nHost: x\r\n\r\n"
	rest := []byte(req2 + req3)

	for _, tc := range []struct {
		name string
		src  io.Reader
	}{
		{"bulk", bytes.NewReader(rest)},
		{"byte-by-byte", &oneByteReader{data: rest}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fwd, count := drainCount(t, first, rest, tc.src)
			if !bytes.Equal(fwd, rest) {
				t.Fatalf("bytes not forwarded verbatim:\n got %q\nwant %q", fwd, rest)
			}
			if count != 2 {
				t.Fatalf("expected 2 counted requests (req2+req3), got %d", count)
			}
		})
	}
}

func TestRequestCounter_FailsOpenOnChunked(t *testing.T) {
	first := []byte("GET /a HTTP/1.1\r\nHost: x\r\n\r\n")
	// req#2 is chunked → fail open → req#3 NOT counted.
	rest := []byte("POST /b HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"0\r\n\r\n" + "GET /c HTTP/1.1\r\nHost: x\r\n\r\n")
	fwd, count := drainCount(t, first, rest, bytes.NewReader(rest))
	if !bytes.Equal(fwd, rest) {
		t.Fatalf("bytes not forwarded verbatim under fail-open")
	}
	if count != 1 {
		t.Fatalf("chunked req#2 should count once then fail open (req#3 uncounted); got %d", count)
	}
}

func TestRequestCounter_FailsOpenOnUpgrade(t *testing.T) {
	// req#1 is a websocket upgrade → counter never counts anything after it.
	first := []byte("GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	rest := []byte("\x81\x05hello some opaque websocket frames GET /x HTTP/1.1\r\n\r\n")
	fwd, count := drainCount(t, first, rest, bytes.NewReader(rest))
	if !bytes.Equal(fwd, rest) {
		t.Fatalf("bytes not forwarded verbatim under upgrade passthrough")
	}
	if count != 0 {
		t.Fatalf("upgraded connection should count 0 further requests, got %d", count)
	}
}

func TestRequestCounter_AbortsWhenCapTripped(t *testing.T) {
	first := []byte("GET /a HTTP/1.1\r\nHost: x\r\n\r\n")
	rest := []byte("GET /b HTTP/1.1\r\nHost: x\r\n\r\n" + "GET /c HTTP/1.1\r\nHost: x\r\n\r\n")
	calls := 0
	rc := newRequestCounter(first, func() error {
		calls++
		if calls >= 1 { // cap of 0 beyond first → trip on the very next request
			return errors.New("daily cap")
		}
		return nil
	})
	var out bytes.Buffer
	_, err := io.Copy(&out, rc.wrap(bytes.NewReader(rest)))
	if err == nil {
		t.Fatalf("expected io.Copy to surface the abort error")
	}
	if calls != 1 {
		t.Fatalf("should abort after the first over-cap request, got %d calls", calls)
	}
}

// itoaTest avoids importing strconv just for the test fixtures.
func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
