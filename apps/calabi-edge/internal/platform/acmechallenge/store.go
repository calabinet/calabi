// Package acmechallenge serves ACME http-01 challenge tokens that
// cert-svc broadcasts over NATS.
//
// WHY THIS EXISTS
// ---------------
// When a user self-serves a Let's Encrypt cert for their custom domain,
// cert-svc drives an http-01 issuance: lego places a token and LE then
// validates by fetching http://<domain>/.well-known/acme-challenge/<token>.
// That HTTP request lands on the edge fronting the domain — a DIFFERENT
// process from cert-svc, which holds the token only in memory. cert-svc
// therefore broadcasts (token,keyAuth) on calabi.acme.challenge.present;
// this store caches it so the edge's visitor HTTP listener can answer the
// probe. A matching cleanup subject drops the token after validation.
//
// Tokens are public by design — keyAuth only proves control to the ACME
// server that minted the token — so nothing secret is cached here.
//
// Entries also self-expire (TTL) as a backstop in case a cleanup message
// is dropped.
package acmechallenge

import (
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/calabi/calabi/pkg/certevents"
	eventbus "github.com/calabi/calabi/apps/calabi-edge/internal/bus"
)

// DefaultTTL bounds how long a token lives without an explicit cleanup.
// LE validates within seconds of Present; an hour is generous slack.
const DefaultTTL = time.Hour

// Store caches challenge tokens pushed from cert-svc. Safe for concurrent
// Resolve (listener goroutines) vs. subscribe-handler writes.
type Store struct {
	mu     sync.RWMutex
	tokens map[string]entry
	ttl    time.Duration
	logger *slog.Logger

	present eventbus.Subscription
	cleanup eventbus.Subscription
}

type entry struct {
	keyAuth string
	addedAt time.Time
}

// Start subscribes to the present/cleanup subjects on the bus. The
// caller MUST defer Close(). Returns the first subscribe error.
func Start(logger *slog.Logger, bus eventbus.Bus) (*Store, error) {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Store{
		tokens: make(map[string]entry),
		ttl:    DefaultTTL,
		logger: logger.With("component", "acmechallenge"),
	}
	pres, err := bus.Subscribe(certevents.SubjectACMEChallengePresent, s.onPresent)
	if err != nil {
		return nil, err
	}
	clean, err := bus.Subscribe(certevents.SubjectACMEChallengeCleanup, s.onCleanup)
	if err != nil {
		_ = pres.Drain()
		return nil, err
	}
	s.present = pres
	s.cleanup = clean
	s.logger.Info("acme http-01 challenge serving wired",
		"present", certevents.SubjectACMEChallengePresent,
		"cleanup", certevents.SubjectACMEChallengeCleanup)
	return s, nil
}

func (s *Store) onPresent(m *eventbus.Msg) {
	var ev certevents.ChallengeEvent
	if err := json.Unmarshal(m.Data, &ev); err != nil {
		s.logger.Warn("challenge present: bad payload", "err", err)
		return
	}
	if ev.Token == "" {
		return
	}
	s.mu.Lock()
	s.tokens[ev.Token] = entry{keyAuth: ev.KeyAuth, addedAt: time.Now()}
	s.mu.Unlock()
	s.logger.Info("acme challenge installed", "domain", ev.Domain, "token", ev.Token)
}

func (s *Store) onCleanup(m *eventbus.Msg) {
	var ev certevents.ChallengeEvent
	if err := json.Unmarshal(m.Data, &ev); err != nil {
		s.logger.Warn("challenge cleanup: bad payload", "err", err)
		return
	}
	if ev.Token == "" {
		return
	}
	s.mu.Lock()
	delete(s.tokens, ev.Token)
	s.mu.Unlock()
	s.logger.Debug("acme challenge cleaned", "domain", ev.Domain, "token", ev.Token)
}

// Resolve returns the keyAuth for a token, or ok=false on miss/expiry.
// This is the closure the HTTP listener calls for
// /.well-known/acme-challenge/<token>.
func (s *Store) Resolve(token string) (string, bool) {
	s.mu.RLock()
	e, ok := s.tokens[token]
	s.mu.RUnlock()
	if !ok {
		return "", false
	}
	if time.Since(e.addedAt) > s.ttl {
		s.mu.Lock()
		delete(s.tokens, token)
		s.mu.Unlock()
		return "", false
	}
	return e.keyAuth, true
}

// Close drains the subscriptions. Idempotent-ish (safe to call once).
func (s *Store) Close() error {
	if s.present != nil {
		_ = s.present.Drain()
	}
	if s.cleanup != nil {
		_ = s.cleanup.Drain()
	}
	return nil
}
