package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

const (
	browserPairTTL    = 5 * time.Minute
	browserIdleTTL    = 30 * time.Minute
	browserSessionTTL = 8 * time.Hour
	browserAuthLimit  = 16
)

// Authentication state is deliberately independent of the file agent/workspace.
// Restart invalidates browser access, but logout and expiry never stop transfers.
// Only one-way verifiers are retained. No browser can issue a pairing capability.
type browserAuth struct {
	mu       sync.Mutex
	now      func() time.Time
	pairs    map[[32]byte]time.Time
	sessions map[[32]byte]browserSession
}

type browserSession struct {
	ID         string    `json:"id"`
	Label      string    `json:"label"`
	Created    time.Time `json:"created"`
	Expires    time.Time `json:"expires"`
	LastActive time.Time `json:"last_active"`
	Host       string    `json:"-"`
	Current    bool      `json:"current"`
}

func newBrowserAuth() *browserAuth {
	return &browserAuth{now: time.Now, pairs: make(map[[32]byte]time.Time), sessions: make(map[[32]byte]browserSession)}
}

func browserSecret() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func browserVerifier(secret string) ([32]byte, bool) {
	if len(secret) != 64 {
		return [32]byte{}, false
	}
	if _, err := hex.DecodeString(secret); err != nil {
		return [32]byte{}, false
	}
	return sha256.Sum256([]byte(secret)), true
}

func (a *browserAuth) prune(now time.Time) {
	for h, end := range a.pairs {
		if !now.Before(end) {
			delete(a.pairs, h)
		}
	}
	for h, s := range a.sessions {
		if !now.Before(s.Expires) || !now.Before(s.LastActive.Add(browserIdleTTL)) {
			delete(a.sessions, h)
		}
	}
}

func (a *browserAuth) issuePair() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.prune(now)
	if len(a.pairs) >= browserAuthLimit {
		return "", errors.New("too many pending pairings; revoke browser access or wait five minutes")
	}
	secret, err := browserSecret()
	if err != nil {
		return "", err
	}
	h, _ := browserVerifier(secret)
	a.pairs[h] = now.Add(browserPairTTL)
	return secret, nil
}

func (a *browserAuth) exchange(secret, host, label string) (string, browserSession, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.prune(now)
	h, ok := browserVerifier(secret)
	if !ok {
		return "", browserSession{}, false
	}
	if _, ok = a.pairs[h]; !ok || len(a.sessions) >= browserAuthLimit {
		return "", browserSession{}, false
	}
	token, err := browserSecret()
	if err != nil {
		return "", browserSession{}, false
	}
	verifier, _ := browserVerifier(token)
	if len(label) > 120 {
		label = label[:120]
	}
	s := browserSession{ID: hex.EncodeToString(verifier[:16]), Host: host, Label: label, Created: now, LastActive: now, Expires: now.Add(browserSessionTTL)}
	delete(a.pairs, h) // consume atomically with session creation
	a.sessions[verifier] = s
	return token, s, true
}

func (a *browserAuth) authorize(token, host string, touch bool) (browserSession, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.prune(a.now())
	h, ok := browserVerifier(token)
	if !ok {
		return browserSession{}, false
	}
	s, ok := a.sessions[h]
	if !ok || s.Host != host {
		return browserSession{}, false
	}
	if touch {
		s.LastActive = a.now()
		a.sessions[h] = s
	}
	return s, true
}

func (a *browserAuth) list(token, host string) []browserSession {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.prune(a.now())
	h, _ := browserVerifier(token)
	out := make([]browserSession, 0, len(a.sessions))
	for id, s := range a.sessions {
		if s.Host == host {
			s.Current = id == h
			out = append(out, s)
		}
	}
	return out
}

func (a *browserAuth) revoke(token, host, id string, all bool) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.prune(a.now())
	h, ok := browserVerifier(token)
	if !ok {
		return false
	}
	s, ok := a.sessions[h]
	if !ok || s.Host != host {
		return false
	}
	if all {
		clear(a.sessions)
		clear(a.pairs)
		return true
	}
	for h, s := range a.sessions {
		if s.Host == host && s.ID == id {
			delete(a.sessions, h)
			return true
		}
	}
	return false
}

func (a *browserAuth) revokeAll() {
	a.mu.Lock()
	defer a.mu.Unlock()
	clear(a.pairs)
	clear(a.sessions)
}
