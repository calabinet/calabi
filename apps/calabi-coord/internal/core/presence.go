package core

import "sync"

// Presence tracks which nodes currently hold a live control stream (PullNetMap) —
// i.e. which are ONLINE right now. This is distinct from the admin Disabled flag
// (an operator kill switch) and from LastSeen (when a node last registered): a
// node that quits shows offline here even though it stays "not disabled".
//
// In-memory and process-local: presence is ephemeral connection state, never
// persisted. A coord restart drops all presence, but every node's reconnect loop
// re-opens its stream within seconds and repopulates it. Safe for concurrent use.
//
// A per-node COUNT (not a bool) tolerates a brief reconnect overlap where a node's
// new stream opens before its old stream's teardown is observed — the node stays
// online until the last stream releases.
type Presence struct {
	mu     sync.Mutex
	counts map[int64]int
}

// NewPresence builds an empty tracker.
func NewPresence() *Presence {
	return &Presence{counts: make(map[int64]int)}
}

// Connected marks nodeID online and returns a release to call when its stream
// ends (defer it). The returned closure is idempotent, so a double-release (e.g. a
// deferred call plus an explicit one) can't drive the count negative.
func (p *Presence) Connected(nodeID int64) (release func()) {
	if p == nil {
		return func() {}
	}
	p.mu.Lock()
	p.counts[nodeID]++
	p.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			p.mu.Lock()
			if p.counts[nodeID] <= 1 {
				delete(p.counts, nodeID)
			} else {
				p.counts[nodeID]--
			}
			p.mu.Unlock()
		})
	}
}

// IsOnline reports whether nodeID currently holds at least one live stream. Safe
// on a nil receiver (reports false), so callers needn't nil-check.
func (p *Presence) IsOnline(nodeID int64) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.counts[nodeID] > 0
}

// Online returns the set of online ids among those given — one lock acquisition
// for a whole node list. Nil receiver yields an empty set.
func (p *Presence) Online(ids []int64) map[int64]bool {
	out := make(map[int64]bool, len(ids))
	if p == nil {
		return out
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, id := range ids {
		if p.counts[id] > 0 {
			out[id] = true
		}
	}
	return out
}
