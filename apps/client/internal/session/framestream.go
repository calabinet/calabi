package session

import (
	"io"
	"sync"

	proto "github.com/calabi/calabi/pkg/protocol"
)

// frameStream is a serialized writer / reader over the control stream.
// Symmetric with apps/calabi-edge/internal/session.frameStream; both are
// small enough to keep duplicated rather than introducing a third package.
type frameStream struct {
	w   io.ReadWriteCloser
	wmu sync.Mutex
	rmu sync.Mutex
}

func newFrameStream(w io.ReadWriteCloser) *frameStream {
	return &frameStream{w: w}
}

func (s *frameStream) Write(f proto.Frame) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_, err := proto.WriteFrame(s.w, f)
	return err
}

func (s *frameStream) WritePayload(t proto.FrameType, payload any) error {
	f, err := proto.EncodePayload(t, payload)
	if err != nil {
		return err
	}
	return s.Write(f)
}

func (s *frameStream) Read() (proto.Frame, error) {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	return proto.ReadFrame(s.w)
}

func (s *frameStream) Close() error { return s.w.Close() }
