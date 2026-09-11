package core

import "sync"

// Notifier lets PullNetMap streams learn that their meshnet's topology changed
// (a node joined/left, or endpoints moved) so they re-pull and re-push a fresh
// NetMap without the client reconnecting. It carries no data — just a coalescing
// "something changed" signal per subscriber, keyed by meshnet.
//
// Deployment-agnostic: the same mechanism serves the SaaS and the self-hosted
// coordinator. (A multi-instance SaaS deployment will later back Bump with a
// NATS fan-out so a change on one coord instance reaches streams pinned to
// another; MESH.8. Single-instance — including every self-hosted coordinator —
// needs only this in-process notifier.)
type Notifier struct {
	mu sync.Mutex
	// nextSub hands each subscription its own key. Keying by NODE id instead
	// looked natural — one stream per node — but a node legitimately holds two
	// for a moment: the reconnect that Presence is explicitly built to tolerate
	// opens the new stream before the old one's teardown runs. The old stream's
	// unsubscribe then deleted the map entry the NEW stream had just installed,
	// leaving a live stream that Bump could no longer reach (audit finding
	// MESH-11). It kept serving the node its stale netmap — including an ACL an
	// admin had just tightened — until the 15-minute grant refresh happened to
	// re-push, and a node could provoke that state deliberately.
	nextSub int64
	subs    map[MeshnetID]map[int64]chan struct{} // meshnet -> subscription id -> signal
}

// NewNotifier returns an empty notifier.
func NewNotifier() *Notifier {
	return &Notifier{subs: make(map[MeshnetID]map[int64]chan struct{})}
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
	}
	m[id] = ch
	n.mu.Unlock()

	return ch, func() {
		n.mu.Lock()
		if m := n.subs[t]; m != nil {
			delete(m, id) // only ever its OWN entry
			if len(m) == 0 {
				delete(n.subs, t)
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
	for _, ch := range n.subs[t] {
		select {
		case ch <- struct{}{}:
		default: // already pending — coalesce
		}
	}
}

// BumpAll signals every subscriber across all meshnets to re-pull. Used when a
// change affects potentially everyone — e.g. an ACL policy reload, which can
// alter any node's visible peer set.
func (n *Notifier) BumpAll() {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, m := range n.subs {
		for _, ch := range m {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}
}
