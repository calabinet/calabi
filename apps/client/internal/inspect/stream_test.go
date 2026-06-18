package inspect

import (
	"sync"
	"testing"
	"time"
)

func TestPipeBuf_BlockingReadUntilClose(t *testing.T) {
	p := NewPipeBuf(0)
	var got []byte
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 16)
		for {
			n, err := p.Read(buf)
			if n > 0 {
				got = append(got, buf[:n]...)
			}
			if err != nil {
				return
			}
		}
	}()
	_, _ = p.Write([]byte("hello"))
	_, _ = p.Write([]byte(" world"))
	_ = p.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reader did not exit on close")
	}
	if string(got) != "hello world" {
		t.Fatalf("got %q", string(got))
	}
}

func TestPipeBuf_OverflowDropsAndFlags(t *testing.T) {
	p := NewPipeBuf(10)
	_, _ = p.Write([]byte("01234"))    // 5/10
	_, _ = p.Write([]byte("567890ab")) // 5 fit, 3 dropped
	if !p.Dropped() {
		t.Fatal("expected dropped flag")
	}
	_ = p.Close()
	out, _ := readAll(p)
	if string(out) != "0123456789" {
		t.Fatalf("got %q", string(out))
	}
}

func TestStreamParse_SinglePair(t *testing.T) {
	hl := NewHTTPLog(10, 1024)
	tap := NewHTTPTap(hl, "px-t1")
	req := NewPipeBuf(0)
	resp := NewPipeBuf(0)
	done := tap.StreamParse(req, resp, time.Now())

	_, _ = req.Write([]byte("GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	_, _ = resp.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	// Give the parser a tick to consume the response body.
	if !waitFor(func() bool { return len(hl.Snapshot()) == 1 }, time.Second) {
		t.Fatalf("capture not emitted; got %d", len(hl.Snapshot()))
	}
	caps := hl.Snapshot()
	if caps[0].Method != "GET" || caps[0].ResponseStatus != 200 || caps[0].ResponseBody != "ok" {
		t.Fatalf("bad capture: %+v", caps[0])
	}
	_ = req.Close()
	_ = resp.Close()
	<-done
}

func TestStreamParse_PipelinedPairs(t *testing.T) {
	hl := NewHTTPLog(10, 1024)
	tap := NewHTTPTap(hl, "px-t2")
	req := NewPipeBuf(0)
	resp := NewPipeBuf(0)
	done := tap.StreamParse(req, resp, time.Now())

	_, _ = req.Write([]byte(
		"GET /a HTTP/1.1\r\nHost: x\r\n\r\n" +
			"GET /b HTTP/1.1\r\nHost: x\r\n\r\n",
	))
	_, _ = resp.Write([]byte(
		"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA" +
			"HTTP/1.1 404 Not Found\r\nContent-Length: 1\r\n\r\nB",
	))
	if !waitFor(func() bool { return len(hl.Snapshot()) == 2 }, time.Second) {
		t.Fatalf("expected 2 captures, got %d", len(hl.Snapshot()))
	}
	_ = req.Close()
	_ = resp.Close()
	<-done

	// Snapshot is newest-first.
	caps := hl.Snapshot()
	if caps[0].Path != "/b" || caps[0].ResponseStatus != 404 {
		t.Fatalf("cap[0] wrong: %+v", caps[0])
	}
	if caps[1].Path != "/a" || caps[1].ResponseStatus != 200 {
		t.Fatalf("cap[1] wrong: %+v", caps[1])
	}
}

func TestStreamParse_ExitsOnClose(t *testing.T) {
	hl := NewHTTPLog(10, 1024)
	tap := NewHTTPTap(hl, "px-t3")
	req := NewPipeBuf(0)
	resp := NewPipeBuf(0)
	done := tap.StreamParse(req, resp, time.Now())

	// Close before any data — parser must exit, not hang.
	_ = req.Close()
	_ = resp.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("parser hung after close with no data")
	}
	if got := len(hl.Snapshot()); got != 0 {
		t.Fatalf("expected 0 captures, got %d", got)
	}
}

// helpers

func waitFor(cond func() bool, max time.Duration) bool {
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

func readAll(p *PipeBuf) ([]byte, error) {
	var out []byte
	buf := make([]byte, 32)
	for {
		n, err := p.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err != nil {
			if err.Error() == "EOF" {
				return out, nil
			}
			return out, err
		}
	}
}

var _ = sync.Mutex{} // appease "imported and not used" if no other ref above
