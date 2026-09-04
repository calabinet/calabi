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
	mu   sync.Mutex
	subs map[MeshnetID]map[int64]chan struct{}
}

// NewNotifier returns an empty notifier.
func NewNotifier() *Notifier {
	return &Notifier{subs: make(map[MeshnetID]map[int64]chan struct{})}
}

// Subscribe registers a stream for meshnet t under nodeID. It returns a signal
// channel (buffered depth 1, so signals coalesce) and an unsubscribe func the
// caller MUST invoke when the stream ends.
func (n *Notifier) Subscribe(t MeshnetID, nodeID int64) (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	n.mu.Lock()
	m := n.subs[t]
	if m == nil {
		m = make(map[int64]chan struct{})
		n.subs[t] = m
	}
	m[nodeID] = ch
	n.mu.Unlock()

	return ch, func() {
		n.mu.Lock()
		if m := n.subs[t]; m != nil {
			delete(m, nodeID)
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
