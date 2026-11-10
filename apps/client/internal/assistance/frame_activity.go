package assistance

import (
	"context"
	"time"
)

// TrackFrame is called by the serialized owner before dispatching its
// single frame worker. Completion may run on that worker. A late completion
// touches only the particular renewal and frame deadline it started with.
func (c *Controller) TrackFrame(id string, epoch int) func(Reply, error) {
	r := c.active
	if r == nil || r.id != id || r.epoch != epoch {
		return func(Reply, error) {}
	}
	now := time.Since(r.start)
	deadline := int64(now + 3*time.Second)
	r.frameUntil.Store(deadline)
	return func(reply Reply, err error) {
		var tail int64
		finished := time.Since(r.start)
		if err == nil && reply.State == "control" && reply.Epoch == epoch && int64(finished) < deadline {
			tail = int64(finished + 600*time.Millisecond)
		}
		r.frameUntil.CompareAndSwap(deadline, tail)
	}
}

// The ordinary-user agent has one request/reply pipe. Returning a pending result
// lets it service ordered input without waiting for the remote frame body.
type frameResult struct {
	reply Reply
	err   error
}
type pendingFrame struct {
	owner  *renewal
	cancel context.CancelFunc
	result chan frameResult
}

func (s *Controller) discardFrame() {
	if s.frame != nil {
		s.frame.cancel()
		s.frame = nil
	}
}
func (s *Controller) nextFrame(ctx context.Context, route Route, c Command) (Reply, error) {
	c.Op = "frame_delta"
	r := s.active
	if r != nil {
		select {
		case <-r.done:
			s.stop()
			r = nil
		default:
		}
	}
	if r == nil || r.id != c.ID || r.epoch != c.Epoch {
		s.discardFrame()
		// Re-read the host's state through the ordinary control path.
		return s.Do(ctx, s.client, route.Remote, route.Port, c)
	}
	if f := s.frame; f != nil {
		if f.owner != r {
			s.discardFrame()
		} else {
			select {
			case res := <-f.result:
				s.discardFrame()
				if res.err != nil || res.reply.State != "control" || res.reply.Epoch != r.epoch {
					s.stop()
				}
				return res.reply, res.err
			default:
				return Reply{FramePending: true}, nil
			}
		}
	}
	frameCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	f := &pendingFrame{owner: r, cancel: cancel, result: make(chan frameResult, 1)}
	s.frame = f
	finish := s.TrackFrame(c.ID, c.Epoch)
	client := s.client
	go func() {
		defer cancel()
		reply, err := Exchange(frameCtx, client, route.Remote, route.Port, c)
		finish(reply, err)
		f.result <- frameResult{reply, err}
	}()
	return Reply{FramePending: true}, nil
}
