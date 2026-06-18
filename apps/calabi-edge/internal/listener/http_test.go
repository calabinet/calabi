package listener

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// TestSniffHTTPReturnsImmediately is a regression test for the bug
// where bufio.Reader.Peek(8192) blocked until the buffer was full,
// stalling sniff for the entire visitor read deadline.
//
// We send a short HTTP/1.1 GET and then DO NOT write more bytes (just like
// curl, which waits for a response on the same conn). sniffHTTP MUST
// return as soon as the \r\n\r\n terminator arrives, not wait for more.
func TestSniffHTTPReturnsImmediately(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_, _ = io.WriteString(client,
			"GET /foo HTTP/1.1\r\n"+
				"Host: example.calabi.app:8080\r\n"+
				"User-Agent: curl/8.13.0\r\n"+
				"Accept: */*\r\n"+
				"\r\n")
		// Intentionally do NOT close -- mimic curl waiting for response.
		time.Sleep(5 * time.Second)
	}()

	done := make(chan struct {
		head            []byte
		host, m, p      string
		err             error
		elapsedMillisec int64
	}, 1)
	go func() {
		start := time.Now()
		br := bufio.NewReaderSize(server, 8192)
		head, host, method, path, err := sniffHTTP(br)
		done <- struct {
			head            []byte
			host, m, p      string
			err             error
			elapsedMillisec int64
		}{head, host, method, path, err, time.Since(start).Milliseconds()}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("sniff failed: %v", r.err)
		}
		if r.elapsedMillisec > 500 {
			t.Fatalf("sniff took %d ms; should be near-instant", r.elapsedMillisec)
		}
		if r.host != "example.calabi.app:8080" {
			t.Errorf("host=%q", r.host)
		}
		if r.m != "GET" || r.p != "/foo" {
			t.Errorf("method=%q path=%q", r.m, r.p)
		}
		if !bytes.HasSuffix(r.head, []byte("\r\n\r\n")) {
			t.Errorf("head not terminated by \\r\\n\\r\\n: %q", r.head)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("sniff did not return within 2 s — the Peek(8192) bug is back")
	}
}

// TestSniffHTTPRejectsOversizeHead protects the 16 KiB ceiling.
func TestSniffHTTPRejectsOversizeHead(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_, _ = io.WriteString(client, "GET / HTTP/1.1\r\nHost: x\r\nX-Junk: ")
		_, _ = io.WriteString(client, strings.Repeat("a", 17*1024))
		_, _ = io.WriteString(client, "\r\n\r\n")
	}()

	br := bufio.NewReaderSize(server, 8192)
	_, _, _, _, err := sniffHTTP(br)
	if err == nil {
		t.Fatalf("expected error on oversize head")
	}
}

// TestSniffHTTPRejectsClosedConn confirms EOF before headers is an error.
func TestSniffHTTPRejectsClosedConn(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	go func() {
		// Close immediately, no bytes sent.
		_ = client.Close()
	}()

	br := bufio.NewReaderSize(server, 8192)
	_, _, _, _, err := sniffHTTP(br)
	if err == nil {
		t.Fatalf("expected error on closed conn before headers")
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Logf("warn: got %v (acceptable as long as non-nil)", err)
	}
}
