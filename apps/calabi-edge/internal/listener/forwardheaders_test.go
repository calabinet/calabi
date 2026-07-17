package listener

import (
	"io"
	"strings"
	"testing"
)

func hasHeader(head, name, value string) bool {
	return strings.Contains(head, "\r\n"+name+": "+value+"\r\n")
}

func TestInjectForwardHeaders(t *testing.T) {
	t.Run("no inbound XFF → set; real-ip/proto/host added", func(t *testing.T) {
		in := "GET /p HTTP/1.1\r\nHost: app.example.com\r\nUser-Agent: x\r\n\r\n"
		out := string(injectForwardHeaders([]byte(in), "203.0.113.7", "app.example.com", false))
		if !hasHeader(out, "X-Forwarded-For", "203.0.113.7") {
			t.Fatalf("XFF not set: %q", out)
		}
		if !hasHeader(out, "X-Real-IP", "203.0.113.7") {
			t.Fatalf("X-Real-IP not set: %q", out)
		}
		if !hasHeader(out, "X-Forwarded-Proto", "http") {
			t.Fatalf("X-Forwarded-Proto not set: %q", out)
		}
		if !hasHeader(out, "X-Forwarded-Host", "app.example.com") {
			t.Fatalf("X-Forwarded-Host not set: %q", out)
		}
		// Original headers + request line preserved, single terminator.
		if !strings.HasPrefix(out, "GET /p HTTP/1.1\r\n") || !strings.Contains(out, "User-Agent: x\r\n") {
			t.Fatalf("request line / original headers lost: %q", out)
		}
		if !strings.HasSuffix(out, "\r\n\r\n") || strings.Count(out, "\r\n\r\n") != 1 {
			t.Fatalf("header terminator malformed: %q", out)
		}
	})

	t.Run("existing XFF chain → real IP appended at END", func(t *testing.T) {
		in := "GET / HTTP/1.1\r\nHost: h\r\nX-Forwarded-For: 1.1.1.1, 2.2.2.2\r\n\r\n"
		out := string(injectForwardHeaders([]byte(in), "9.9.9.9", "h", false))
		if !hasHeader(out, "X-Forwarded-For", "1.1.1.1, 2.2.2.2, 9.9.9.9") {
			t.Fatalf("XFF should append connecting IP at the end: %q", out)
		}
		if strings.Count(out, "X-Forwarded-For:") != 1 {
			t.Fatalf("XFF must not be duplicated: %q", out)
		}
	})

	t.Run("https scheme", func(t *testing.T) {
		out := string(injectForwardHeaders([]byte("GET / HTTP/1.1\r\nHost: h\r\n\r\n"), "5.6.7.8", "h", true))
		if !hasHeader(out, "X-Forwarded-Proto", "https") {
			t.Fatalf("expected https proto: %q", out)
		}
	})

	t.Run("inbound X-Real-IP overwritten; proto/host preserved", func(t *testing.T) {
		in := "GET / HTTP/1.1\r\nHost: h\r\nX-Real-IP: 6.6.6.6\r\n" +
			"X-Forwarded-Proto: https\r\nX-Forwarded-Host: orig.example.com\r\n\r\n"
		out := string(injectForwardHeaders([]byte(in), "9.9.9.9", "h", false))
		if !hasHeader(out, "X-Real-IP", "9.9.9.9") || hasHeader(out, "X-Real-IP", "6.6.6.6") {
			t.Fatalf("X-Real-IP must be overwritten with the connecting IP: %q", out)
		}
		// A fronting proxy's proto/host survive (set-only-when-absent).
		if !hasHeader(out, "X-Forwarded-Proto", "https") {
			t.Fatalf("inbound X-Forwarded-Proto should be preserved: %q", out)
		}
		if !hasHeader(out, "X-Forwarded-Host", "orig.example.com") {
			t.Fatalf("inbound X-Forwarded-Host should be preserved: %q", out)
		}
	})

	t.Run("empty visitor IP → unchanged", func(t *testing.T) {
		in := "GET / HTTP/1.1\r\nHost: h\r\n\r\n"
		if got := string(injectForwardHeaders([]byte(in), "", "h", false)); got != in {
			t.Fatalf("empty IP must be a no-op: %q", got)
		}
	})
}

// Keep-alive requests #2.N get the forwarding headers too, via wrapHeadTransform.
func TestWrapHeadTransform_ForwardHeadersAllRequests(t *testing.T) {
	xform := func(h []byte) []byte { return injectForwardHeaders(h, "203.0.113.7", "h", false) }
	firstHead := []byte("POST /1 HTTP/1.1\r\nContent-Length: 5\r\n\r\n")
	wire := "HELLO" + // request #1 body (passes verbatim)
		"GET /2 HTTP/1.1\r\nHost: h\r\n\r\n" +
		"GET /3 HTTP/1.1\r\nHost: h\r\n\r\n"
	out, err := io.ReadAll(wrapHeadTransform(strings.NewReader(wire), xform, firstHead))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	s := string(out)
	if !strings.HasPrefix(s, "HELLO") {
		t.Fatalf("request #1 body must pass through verbatim: %q", s)
	}
	if strings.Count(s, "X-Forwarded-For: 203.0.113.7\r\n") != 2 {
		t.Fatalf("both keep-alive requests #2 and #3 must get XFF: %q", s)
	}
}
