// Package accesslog is the seam between the visitor-facing listeners (open
// tree) and the platform's tunnel access log (internal/platform/access).
//
// It exists because the listeners must NOT import internal/platform/*: that
// half is the hosted product, and the data plane builds without it. So the
// listeners call Note() here, and the platform side registers a sink at boot.
// With no sink registered — a community build, or a deployment with access
// records switched off — Note is an atomic load and a nil check.
//
// The outcome vocabulary lives here rather than in the platform package for
// the same reason: it is the listeners that decide what happened to a visitor,
// so the words belong on their side of the seam. platform/access re-declares
// the same four values as its own typed constants and validates on the way in,
// so a typo on either side cannot quietly widen the stored table's key space.
package accesslog

import (
	"sync/atomic"
	"time"
)

// Outcomes. Exactly four, and deliberately coarse: each one is a DIMENSION of
// a stored row, so a fifth value is a schema decision, not a logging detail.
const (
	// Allowed — the connection reached the tunnel owner's machine.
	Allowed = "allowed"
	// DeniedIP — refused by the tunnel's IP allow/deny policy.
	DeniedIP = "denied_ip"
	// DeniedAuth — refused for missing or invalid credentials (basic auth,
	// OAuth). "Who kept failing to log in to our staging box" is one of the
	// questions this log exists to answer.
	DeniedAuth = "denied_auth"
	// DeniedRate — refused by the tunnel's own connection-rate cap.
	//
	// Only the per-tunnel cap the OWNER configured. The platform's anti-abuse
	// limiters are deliberately NOT reported: they are hidden from users by
	// design, and surfacing them in a
	// per-tunnel log the owner reads would leak the shape of an internal
	// defence one refusal at a time.
	DeniedRate = "denied_rate"
)

// Sink receives one record per visitor connection.
//
// Implementations must be safe for concurrent use and must not block: this is
// called on the accept path of every visitor connection, so a slow sink is a
// slow website.
type Sink interface {
	NoteAccess(orgID, tunnelID int64, visitorIP, outcome string, at time.Time)
}

// holder lets an interface value live in an atomic.Pointer.
type holder struct{ sink Sink }

var current atomic.Pointer[holder]

// SetSink installs the process-wide sink. Passing nil removes it, which is how
// a deployment turns the access log off without touching any call site.
func SetSink(s Sink) {
	if s == nil {
		current.Store(nil)
		return
	}
	current.Store(&holder{sink: s})
}

// Note records one visitor connection's outcome. A no-op when no sink is
// installed.
func Note(orgID, tunnelID int64, visitorIP, outcome string) {
	h := current.Load()
	if h == nil || h.sink == nil {
		return
	}
	h.sink.NoteAccess(orgID, tunnelID, visitorIP, outcome, time.Now())
}
