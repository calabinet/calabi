package session

import (
	"io"
	"sync"

	proto "github.com/calabi/calabi/pkg/protocol"
)

// frameStream wraps a single ReadWriteCloser with Calabi frame codec
// semantics and serializes concurrent writers.
//
// The control stream is shared by handshake, heartbeat, NEW_PROXY, and
// NEW_CONN goroutines; writes MUST not interleave.
type frameStream struct {
	w   io.ReadWriteCloser
	mu  sync.Mutex // serializes WriteFrame
	rmu sync.Mutex // serializes ReadFrame (single reader expected, but defensive)
}

func newFrameStream(w io.ReadWriteCloser) *frameStream {
	return &frameStream{w: w}
}

// Write writes a fully-formed Frame.
func (s *frameStream) Write(f proto.Frame) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := proto.WriteFrame(s.w, f)
	return err
}

// WritePayload encodes payload as JSON and writes one frame of type t.
func (s *frameStream) WritePayload(t proto.FrameType, payload any) error {
	f, err := proto.EncodePayload(t, payload)
	if err != nil {
		return err
	}
	return s.Write(f)
}

// Read returns the next inbound frame.
func (s *frameStream) Read() (proto.Frame, error) {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	return proto.ReadFrame(s.w)
}

// Close shuts the underlying stream.
func (s *frameStream) Close() error { return s.w.Close() }
