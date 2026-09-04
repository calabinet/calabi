package core

import (
	"sync"
	"time"
)

// Service health (F3b) — what a node OBSERVES about the services it declares.
//
// The question it answers: an admin writes a rule naming a service, confirms it,
// and it still does not work. The usual cause is an application bound to
// 127.0.0.1 only — opening the port in the packet filter changes nothing,
// because a peer's packet arrives on the tun interface addressed to the overlay
// address and finds no socket there. Only the node can tell that apart from "the
// app is down", by dialing both its own target and its own overlay address.
//
// IN MEMORY, current value only, exactly like Presence. Two reasons, and the
// second is the one that matters:
//
//   - Writing it would mean a row update per service per node per minute, to
//     store something that is meaningless a minute later.
//   - A persisted series of "which port answered when" is a record of what ran
//     on someone's machine over time. rule is current value over history,
//     and this is precisely the sort of thing that rule is about.
//
// A restart therefore forgets everything, and every node refills it within its
// reporting interval. Until then the console shows nothing for that service,
// which is the honest state: not "unhealthy", just not yet observed.

// ServiceHealth is one service as its own node sees it.
type ServiceHealth struct {
	// TargetOK: the application answers where the machine itself dials it.
	TargetOK bool `json:"target_ok"`
	// MeshOK: the machine reaches the service on its OWN overlay address, the
	// way a peer would. TargetOK && !MeshOK is the loopback-only case.
	MeshOK bool `json:"mesh_ok"`
	// At is when the node reported it.
	At time.Time `json:"at"`
}

// serviceHealthKey identifies one service without depending on its row id — a
// node re-declaring a service can produce a new id, and health follows the name
// on that machine, which is what the console renders against.
type serviceHealthKey struct {
	node int64
	name string
}

// ServiceHealthTracker holds the latest observation per (node, service).
type ServiceHealthTracker struct {
	mu sync.RWMutex
	m  map[serviceHealthKey]ServiceHealth
}

func NewServiceHealthTracker() *ServiceHealthTracker {
	return &ServiceHealthTracker{m: map[serviceHealthKey]ServiceHealth{}}
}

// Report records a node's observations, REPLACING everything previously known
// about that node's services.
//
// Replace rather than merge: the report is the node's whole current view, so a
// service it no longer mentions is one it no longer has, and keeping the old
// entry would leave a stale green badge on something that is gone.
func (t *ServiceHealthTracker) Report(nodeID int64, in map[string]ServiceHealth, now time.Time) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for k := range t.m {
		if k.node == nodeID {
			delete(t.m, k)
		}
	}
	for name, h := range in {
		h.At = now
		t.m[serviceHealthKey{node: nodeID, name: name}] = h
	}
}

// Get returns a node's observation of one service. ok=false means nothing has
// been reported — which is NOT the same as unhealthy, and callers must render
// the difference.
func (t *ServiceHealthTracker) Get(nodeID int64, name string) (ServiceHealth, bool) {
	if t == nil {
		return ServiceHealth{}, false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	h, ok := t.m[serviceHealthKey{node: nodeID, name: name}]
	return h, ok
}

// Forget drops a node's observations (used when a node is deleted, so a later
// node reusing the id can't inherit them).
func (t *ServiceHealthTracker) Forget(nodeID int64) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for k := range t.m {
		if k.node == nodeID {
			delete(t.m, k)
		}
	}
}
