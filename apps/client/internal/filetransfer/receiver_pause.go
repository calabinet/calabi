package filetransfer

import (
	"errors"
	"time"
)

// SetPaused is a local recipient decision. A remote sender may inspect it but
// cannot clear it. Pause retains only acknowledged bytes and the same ticket.
func (r *Receiver) SetPaused(id string, paused bool) error {
	s := r.find(id)
	if s == nil {
		return errors.New("unknown transfer")
	}
	if !s.view().PauseSupported {
		return errors.New("update the sending client to support recipient pause")
	}
	if paused {
		s.pauseRequested.Store(true)
		defer s.pauseRequested.Store(false)
		s.uploadMu.Lock()
		if s.uploadCancel != nil {
			s.uploadCancel()
		}
		s.uploadMu.Unlock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if paused && s.State == "paused" {
		return nil
	}
	if !paused && (s.State == "accepted" || s.State == "receiving") {
		return nil
	}
	if paused && s.State != "accepted" && s.State != "receiving" || !paused && s.State != "paused" {
		return errors.New("transfer cannot be paused or resumed in its current state")
	}
	if r.ctx.Err() != nil || s.ctx.Err() != nil || !r.cfg.Allowed() {
		return errors.New("file receiving is no longer authorized")
	}
	before := s.Transfer
	s.State = "paused"
	if !paused {
		s.State = "accepted"
	}
	s.lastActivity.Store(time.Now().UnixNano())
	s.throughput.reset()
	s.RateBps, s.RemainingSeconds = 0, 0
	if err := r.persist(s); err != nil {
		s.Transfer = before
		s.publish()
		return err
	}
	return nil
}

func (a *Agent) SetReceivePaused(id string, paused bool) error {
	r, err := a.find(id)
	if err != nil {
		return err
	}
	return r.SetPaused(id, paused)
}
