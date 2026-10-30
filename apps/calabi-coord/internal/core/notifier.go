package core

import (
	"sync"
	"time"
)

// Notifier lets PullNetMap streams learn that their meshnet's topology changed
// (a node joined/left, or endpoints moved) so they re-pull and re-push a fresh
// NetMap without the client reconnecting. It carries no data — just a coalescing
// "something changed" signal per subscriber, keyed by meshnet.
//
// Deployment-agnostic: the same mechanism serves the SaaS and the self-hosted
// coordinator. (A multi-instance SaaS deployment will later back Bump with a
// NATS fan-out so a change on one coord instance reaches streams pinned to
// another. Single-instance — including every self-hosted
// coordinator — needs only this in-process notifier.)
type Notifier struct {
	mu sync.Mutex
	// nextSub hands each subscription its own key. Keying by NODE id instead
	// looked natural — one stream per node — but a node legitimately holds two
	// for a moment: the reconnect that Presence is explicitly built to tolerate
	// opens the new stream before the old one's teardown runs. The old stream's
	// unsubscribe then deleted the map entry the NEW stream had just installed,
	// leaving a live stream that Bump could no longer reach.
	// It kept serving the node its stale netmap — including an ACL an
	// admin had just tightened — until the 15-minute grant refresh happened to
	// re-push, and a node could provoke that state deliberately.
	nextSub     int64
	subs        map[MeshnetID]map[int64]chan struct{} // meshnet -> subscription id -> signal
	versions    map[MeshnetID]*notificationVersion
	nextVersion uint64
}

type notificationVersion struct {
	id       uint64
	changed  chan struct{}
	ordinary *time.Timer
}

// NewNotifier returns an empty notifier.
func NewNotifier() *Notifier {
	return &Notifier{subs: make(map[MeshnetID]map[int64]chan struct{}), versions: make(map[MeshnetID]*notificationVersion)}
}

// Subscribe registers a stream for meshnet t. It returns a signal channel
// (buffered depth 1, so signals coalesce) and an unsubscribe func the caller
// MUST invoke when the stream ends.
//
// nodeID identifies the caller for readability at the call site only; the
// subscription is keyed independently so that two streams of the same node
// cannot delete each other's registration.
func (n *Notifier) Subscribe(t MeshnetID, nodeID int64) (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	n.mu.Lock()
	n.nextSub++
	id := n.nextSub
	m := n.subs[t]
	if m == nil {
		m = make(map[int64]chan struct{})
		n.subs[t] = m
		n.nextVersion++
		n.versions[t] = &notificationVersion{id: n.nextVersion, changed: make(chan struct{})}
	}
	m[id] = ch
	n.mu.Unlock()

	return ch, func() {
		n.mu.Lock()
		if m := n.subs[t]; m != nil {
			delete(m, id) // only ever its OWN entry
			if len(m) == 0 {
				delete(n.subs, t)
				v := n.versions[t]
				if v.ordinary != nil {
					v.ordinary.Stop()
				}
				close(v.changed)
				delete(n.versions, t)
			}
		}
		n.mu.Unlock()
	}
}

// Bump signals every subscriber in meshnet t to re-pull its NetMap. Non-blocking:
// a subscriber that already has a pending signal is left as-is (coalesced).
func (n *Notifier) Bump(t MeshnetID) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.bumpLocked(t)
}

func (n *Notifier) bumpLocked(t MeshnetID) {
	if v := n.versions[t]; v != nil {
		if v.ordinary != nil {
			v.ordinary.Stop()
			v.ordinary = nil
		}
		close(v.changed)
		n.nextVersion++
		v.id, v.changed = n.nextVersion, make(chan struct{})
	}
	for _, ch := range n.subs[t] {
		select {
		case ch <- struct{}{}:
		default: // already pending — coalesce
		}
	}
}

// Version is valid only while a meshnet has live subscribers. Generations are
// never reused, even after the last subscriber leaves and a new one returns.
func (n *Notifier) Version(t MeshnetID) (uint64, <-chan struct{}) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if v := n.versions[t]; v != nil {
		return v.id, v.changed
	}
	return 0, nil
}

// BumpOrdinary coalesces endpoint-only changes in a fixed 150ms window. The
// default Bump remains immediate for all authorization-affecting mutations.
func (n *Notifier) BumpOrdinary(t MeshnetID) {
	n.mu.Lock()
	defer n.mu.Unlock()
	v := n.versions[t]
	if v == nil || v.ordinary != nil {
		return
	}
	var timer *time.Timer
	timer = time.AfterFunc(150*time.Millisecond, func() {
		n.mu.Lock()
		defer n.mu.Unlock()
		if n.versions[t] == v && v.ordinary == timer {
			n.bumpLocked(t)
		}
	})
	v.ordinary = timer
}

// BumpAll signals every subscriber across all meshnets to re-pull. Used when a
// change affects potentially everyone — e.g. an ACL policy reload, which can
// alter any node's visible peer set.
func (n *Notifier) BumpAll() {
	n.mu.Lock()
	defer n.mu.Unlock()
	for t := range n.subs {
		n.bumpLocked(t)
	}
}
