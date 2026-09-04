package listener

import (
	"io"
	"strings"
	"testing"

	"github.com/calabi/calabi/apps/calabi-edge/internal/policy"
)

func headerPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	p, err := policy.Parse(`{"security":{"request_headers":{"set":{"X-Inject":"1"}}}}`)
	if err != nil || p == nil || !p.HasRequestHeaders() {
		t.Fatalf("parse header policy: p=%v err=%v", p, err)
	}
	return p
}

func TestHeaderRewritingReader_RewritesSubsequentRequests(t *testing.T) {
	pol := headerPolicy(t)
	// Request #1 declared a 5-byte body, so the reader (primed from #1's
	// framing) first skips "HELLO" verbatim, then rewrites #2 and #3.
	firstHead := []byte("POST /1 HTTP/1.1\r\nContent-Length: 5\r\n\r\n")
	wire := "HELLO" +
		"POST /2 HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc" +
		"GET /3 HTTP/1.1\r\nHost: z\r\n\r\n"
	r := wrapHeadTransform(strings.NewReader(wire), pol.RewriteRequestHead, firstHead)
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	s := string(out)
	if !strings.HasPrefix(s, "HELLO") {
		t.Fatalf("request #1 body must pass through verbatim: %q", s)
	}
	if !strings.Contains(s, "abc") {
		t.Fatalf("request #2 body must pass through verbatim: %q", s)
	}
	if strings.Count(s, "X-Inject: 1\r\n") != 2 {
		t.Fatalf("both #2 and #3 heads must be rewritten; got %q", s)
	}
	if !strings.Contains(s, "GET /3 HTTP/1.1\r\n") || !strings.Contains(s, "POST /2 HTTP/1.1\r\n") {
		t.Fatalf("request lines must be preserved: %q", s)
	}
}

func TestHeaderRewritingReader_FailOpenOnChunked(t *testing.T) {
	pol := headerPolicy(t)
	firstHead := []byte("GET /1 HTTP/1.1\r\n\r\n") // no body
	// #2 is chunked: its head is still rewritten (the head is well-framed), but
	// the body — and everything after — passes through verbatim (fail open),
	// so a following #3 is NOT rewritten.
	body := "5\r\nhello\r\n0\r\n\r\n"
	wire := "POST /2 HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n" + body +
		"GET /3 HTTP/1.1\r\nHost: z\r\n\r\n"
	r := wrapHeadTransform(strings.NewReader(wire), pol.RewriteRequestHead, firstHead)
	out, _ := io.ReadAll(r)
	s := string(out)
	if !strings.Contains(s, body+"GET /3 HTTP/1.1\r\nHost: z\r\n\r\n") {
		t.Fatalf("chunked body + following request must pass through verbatim: %q", s)
	}
	if strings.Count(s, "X-Inject: 1\r\n") != 1 {
		t.Fatalf("only the chunked request's head is rewritten, not the fail-open tail: %q", s)
	}
}
