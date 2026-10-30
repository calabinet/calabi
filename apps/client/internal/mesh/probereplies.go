package mesh

import (
	"net/netip"
	"sync/atomic"
	"time"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

const probeReplySlots = 4
const probeReplyQueueLimit = 8192

type queuedProbeReply struct {
	tx       discoTxID
	from     netip.AddrPort
	at       time.Time
	queuedAt time.Time
}
type probeReplyStats struct {
	received  atomic.Uint64
	sent      atomic.Uint64
	limited   atomic.Uint64
	dropped   atomic.Uint64
	coalesced atomic.Uint64
	maxWaitNs atomic.Uint64
}

// Known authenticated peers have at most four queued source endpoints. A
// repeated source replaces its transaction without changing its queue position.
// Unknown identities allocate no state; replies are drained fairly by step.
func (s *probeScheduler) queuePong(key meshproto.DiscoKey, tx discoTxID, from netip.AddrPort) {
	s.queuePongAt(key, tx, from, time.Now())
}
func (s *probeScheduler) queuePongAt(key meshproto.DiscoKey, tx discoTxID, from netip.AddrPort, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.replyStats.received.Add(1)
	sp := s.peers[key]
	if sp == nil || !from.IsValid() || s.paused.Load() {
		s.replyStats.dropped.Add(1)
		return
	}
	for i := range sp.replies {
		if sp.replies[i].from == from {
			sp.replies[i].tx = tx
			sp.replies[i].at = now
			s.replyStats.coalesced.Add(1)
			s.signal()
			return
		}
	}
	if len(sp.replies) >= probeReplySlots || s.replyPending >= probeReplyQueueLimit {
		s.replyStats.dropped.Add(1)
		return
	}
	sp.replies = append(sp.replies, queuedProbeReply{tx: tx, from: from, at: now, queuedAt: now})
	s.replyPending++
	s.signal()
}

// Under s.mu. Replies have a separate device budget (twice the ping rate),
// plus a per-peer six-per-second limit with a three-packet burst.
func (s *probeScheduler) drainPongs(now time.Time) {
	if s.replyRefill.IsZero() {
		s.replyRefill = now
		s.replyTokens = s.burst * 2
	}
	s.replyTokens = min(s.burst*2, s.replyTokens+max(0, now.Sub(s.replyRefill).Seconds())*s.rate*2)
	s.replyRefill = now
	for round := 0; round < probeReplySlots && s.replyPending > 0; round++ {
		for n := 0; n < len(s.order); n++ {
			if s.replyCursor >= len(s.order) {
				s.replyCursor = 0
			}
			sp := s.peers[s.order[s.replyCursor]]
			s.replyCursor++
			if len(sp.replies) == 0 {
				continue
			}
			q := sp.replies[0]
			if now.Sub(q.at) > pendingTTL {
				sp.replies = sp.replies[1:]
				s.replyPending--
				s.replyStats.dropped.Add(1)
				continue
			}
			if sp.replyRefill.IsZero() {
				sp.replyRefill = now
				sp.replyTokens = 3
			}
			sp.replyTokens = min(3, sp.replyTokens+max(0, now.Sub(sp.replyRefill).Seconds())*6)
			sp.replyRefill = now
			if sp.replyTokens < 1 {
				s.replyStats.limited.Add(1)
				continue
			}
			if s.replyTokens < 1 {
				s.replyCursor--
				s.replyStats.limited.Add(1)
				return
			}
			s.replyTokens--
			sp.replyTokens--
			sp.replies = sp.replies[1:]
			s.replyPending--
			if wait := now.Sub(q.queuedAt); wait > 0 {
				for old := s.replyStats.maxWaitNs.Load(); uint64(wait) > old; old = s.replyStats.maxWaitNs.Load() {
					if s.replyStats.maxWaitNs.CompareAndSwap(old, uint64(wait)) {
						break
					}
				}
			}
			if s.reply(sp.key, q.tx, q.from) == nil {
				s.replyStats.sent.Add(1)
			} else {
				s.replyStats.dropped.Add(1)
			}
		}
	}
}
