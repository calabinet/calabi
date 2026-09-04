package policy

import (
	"strings"
	"testing"
)

func TestRewriteRequestHead(t *testing.T) {
	cfg := `{"security":{"request_headers":{` +
		`"set":{"X-Inject":"hello","Host":"upstream.local"},` +
		`"remove":["Cookie","X-Drop"]}}}`
	p, err := Parse(cfg)
	if err != nil || p == nil || !p.HasRequestHeaders() {
		t.Fatalf("parse: p=%v err=%v", p, err)
	}
	// A header-only policy reports no IP / auth / rate rules.
	if p.HasIPRules() || p.HasBasicAuth() || p.HasRateLimit() {
		t.Fatalf("header-only policy must report no other rules")
	}

	in := "GET /path HTTP/1.1\r\n" +
		"Host: orig.example\r\n" +
		"Cookie: secret=1\r\n" +
		"X-Keep: yes\r\n" +
		"X-Drop: bye\r\n\r\n"
	out := string(p.RewriteRequestHead([]byte(in)))

	if !strings.HasPrefix(out, "GET /path HTTP/1.1\r\n") {
		t.Fatalf("request line not preserved: %q", out)
	}
	if !strings.Contains(out, "Host: upstream.local\r\n") || strings.Contains(out, "orig.example") {
		t.Fatalf("Host not replaced in place: %q", out)
	}
	if strings.Count(out, "Host:") != 1 {
		t.Fatalf("expected exactly one Host header: %q", out)
	}
	if strings.Contains(out, "Cookie:") || strings.Contains(out, "X-Drop:") {
		t.Fatalf("removed headers still present: %q", out)
	}
	if !strings.Contains(out, "X-Keep: yes\r\n") {
		t.Fatalf("untouched header dropped: %q", out)
	}
	if !strings.Contains(out, "X-Inject: hello\r\n") {
		t.Fatalf("injected header missing: %q", out)
	}
	if !strings.HasSuffix(out, "\r\n\r\n") {
		t.Fatalf("missing blank terminator: %q", out)
	}
}

func TestRewriteRequestHead_CaseInsensitiveAndDedup(t *testing.T) {
	// "set" matches case-insensitively and collapses duplicate occurrences.
	p, _ := Parse(`{"security":{"request_headers":{"set":{"x-id":"1"}}}}`)
	in := "GET / HTTP/1.1\r\nX-ID: old\r\nX-Id: dup\r\n\r\n"
	out := string(p.RewriteRequestHead([]byte(in)))
	if strings.Count(out, "x-id: 1") != 1 || strings.Contains(out, "old") || strings.Contains(out, "dup") {
		t.Fatalf("case-insensitive replace + dedup failed: %q", out)
	}
}

func TestRewriteRequestHead_NoRulesNoChange(t *testing.T) {
	// No request_headers block → nil reqHeaders → input returned unchanged.
	p, _ := Parse(`{"security":{"ip":{"deny":["10.0.0.0/8"]}}}`)
	if p.HasRequestHeaders() {
		t.Fatalf("policy without request_headers must not rewrite")
	}
	in := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	if got := string(p.RewriteRequestHead(in)); got != string(in) {
		t.Fatalf("no-op rewrite changed bytes: %q", got)
	}
	var nilP *Policy
	if string(nilP.RewriteRequestHead(in)) != string(in) {
		t.Fatalf("nil policy must not rewrite")
	}
}

func TestParse_RequestHeaders_InjectionSafe(t *testing.T) {
	// A value carrying CRLF must not smuggle an extra header line; an invalid
	// header name is dropped.
	p, _ := Parse(`{"security":{"request_headers":{"set":{"X-Ok":"a\r\nEvil: 1","Bad Name":"v"}}}}`)
	if p == nil || !p.HasRequestHeaders() {
		t.Fatalf("expected a header policy")
	}
	out := string(p.RewriteRequestHead([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")))
	// The CRLF must be stripped so "Evil: 1" stays part of X-Ok's value and
	// never becomes its own header line.
	if strings.Contains(out, "\nEvil:") {
		t.Fatalf("CRLF in value injected a header line: %q", out)
	}
	if strings.Contains(out, "Bad Name") {
		t.Fatalf("invalid header name should be dropped: %q", out)
	}
	if !strings.Contains(out, "X-Ok: aEvil: 1\r\n") {
		t.Fatalf("expected CRLF stripped from value: %q", out)
	}
}
