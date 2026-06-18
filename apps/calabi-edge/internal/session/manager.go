package session

import (
	"log/slog"
	"sync"
	"sync/atomic"
)

// SessionObserver is the metrics-facing subset of Set that the session
// package depends on. Defined here (not in metrics/) so this package stays
// importable by unit tests without pulling in Prometheus collectors.
//
// A nil observer is a no-op -- helpful for tests that don't care.
type SessionObserver interface {
	OnSessionAccepted()
	OnSessionClosed()
	OnProxyOpened(proxyType string)
	OnProxyClosed(proxyType, reason string)
	SetActiveSessions(n int)
}

// Manager owns the set of live client sessions on an edge node.
//
// It is process-local; introduces a Redis-backed shared cache so
// route lookups can be served by any node in the same region.
type Manager struct {
	logger *slog.Logger

	mu       sync.RWMutex
	sessions map[string]*Session

	nextSeq atomic.Uint64

	obs SessionObserver
}

// NewManager constructs a Manager. obs may be nil.
func NewManager(logger *slog.Logger, obs SessionObserver) *Manager {
	return &Manager{
		logger:   logger.With("component", "session.manager"),
		sessions: make(map[string]*Session),
		obs:      obs,
	}
}

// Register stores s. The caller is responsible for unique IDs.
func (m *Manager) Register(s *Session) {
	m.mu.Lock()
	m.sessions[s.ID] = s
	n := len(m.sessions)
	m.mu.Unlock()
	if m.obs != nil {
		m.obs.OnSessionAccepted()
		m.obs.SetActiveSessions(n)
	}
}

// Unregister removes the session keyed by id.
func (m *Manager) Unregister(id string) {
	m.mu.Lock()
	_, existed := m.sessions[id]
	delete(m.sessions, id)
	n := len(m.sessions)
	m.mu.Unlock()
	if existed && m.obs != nil {
		m.obs.OnSessionClosed()
		m.obs.SetActiveSessions(n)
	}
}

// Observer returns the registered SessionObserver, which may be nil.
func (m *Manager) Observer() SessionObserver { return m.obs }

// Get returns the session with id, or nil.
func (m *Manager) Get(id string) *Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[id]
}

// Count returns the current number of registered sessions.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// NewSessionID mints a unique session id for handshakes.
func (m *Manager) NewSessionID() string {
	return formatID("sess", m.nextSeq.Add(1))
}

// All iterates over a snapshot of sessions.
func (m *Manager) All(f func(*Session) bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, s := range m.sessions {
		if !f(s) {
			return
		}
	}
}

// FindByDeviceID returns the first session matching deviceID, or nil.
// Used by the online-cap evict consumer to map a NATS payload's
// client_id back onto a live session so we can close it. We expect at
// most one session per device on a given edge — Phase A presence
// model assumes a fresh AUTH overwrites any prior live session — but
// iterating all is cheap (Count() is typically <100 per edge) and
// keeps us correct if the assumption ever drifts.
func (m *Manager) FindByDeviceID(deviceID int64) *Session {
	if deviceID == 0 {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, s := range m.sessions {
		if s.DeviceID == deviceID {
			return s
		}
	}
	return nil
}
