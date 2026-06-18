package logging

import (
	"errors"
	"io"
	"testing"
)

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("boom") }

type capWriter struct{ got []byte }

func (c *capWriter) Write(p []byte) (int, error) { c.got = append(c.got, p...); return len(p), nil }

// A failing sink in the MIDDLE (like a service's detached os.Stderr) must not
// stop later sinks (the dashboard hub) from receiving the line — the bug that
// left the /logs page blank while the file had everything.
func TestBestEffortWriter_FailingSinkDoesntStarveOthers(t *testing.T) {
	a, b := &capWriter{}, &capWriter{}
	w := bestEffortWriter([]io.Writer{a, failWriter{}, b})
	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatalf("best-effort writer should never error: %v", err)
	}
	if string(a.got) != "hello" || string(b.got) != "hello" {
		t.Fatalf("both healthy sinks should get the write; a=%q b=%q", a.got, b.got)
	}
}
