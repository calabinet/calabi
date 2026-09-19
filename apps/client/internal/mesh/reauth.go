package mesh

import (
	"errors"
	"sync"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// ErrRegister wraps a session that ended at registration — the coordinator
// refused this device, as opposed to a session that registered and later lost
// its stream. errors.Is tells the two apart; the gRPC status is wrapped too.
var ErrRegister = errors.New("mesh: register")

// ReauthState remembers, across sessions, which node this device already is and
// whether its coordinator lets it come back by proof of its node key alone. A Controller is
// built per session; this outlives them, so the second session onward does not
// need the auth key at all.
//
// Scope it to one meshnet: a node id means nothing in another, so whoever owns
// it makes a new one when the meshnet changes (an org switch, a different
// server).
type ReauthState struct {
	mu       sync.Mutex
	nodeID   int64
	offered  bool
	onChange func(nodeID int64, offered bool)
}

// NewReauthState starts from what an earlier run recorded (0, false for none).
// onChange, if set, is called whenever a registration changes the record — the
// phone persists it, so a device that has forgotten its auth key can still come
// back after a restart.
func NewReauthState(nodeID int64, offered bool, onChange func(nodeID int64, offered bool)) *ReauthState {
	return &ReauthState{nodeID: nodeID, offered: offered, onChange: onChange}
}

// apply sets p up to try re-registering by proof alone when that is known to
// work.
func (s *ReauthState) apply(p *RegisterParams) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p.NodeID, p.Reauth = s.nodeID, s.offered && s.nodeID != 0
}

// record takes in a successful registration.
func (s *ReauthState) record(reg Registration) {
	if s == nil {
		return
	}
	offered := reg.Capabilities.Supports(meshproto.CapNodeReauth)
	s.mu.Lock()
	changed := s.nodeID != reg.NodeID || s.offered != offered
	s.nodeID, s.offered = reg.NodeID, offered
	notify := s.onChange
	s.mu.Unlock()
	if changed && notify != nil {
		notify(reg.NodeID, offered)
	}
}

// Offered reports whether the coordinator has agreed that this device may come
// back by proof alone — the condition for forgetting an auth key.
func (s *ReauthState) Offered() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.offered && s.nodeID != 0
}
