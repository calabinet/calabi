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
	"strconv"
	"strings"
	"sync"
	"time"

	eventbus "github.com/calabinet/calabi/apps/calabi-edge/internal/bus"
	"github.com/calabinet/calabi/pkg/certevents"
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
	domain  string
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
	s.tokens[ev.Token] = entry{
		keyAuth: ev.KeyAuth,
		domain:  strings.ToLower(strings.TrimSpace(ev.Domain)),
		addedAt: time.Now(),
	}
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

// Resolve returns the keyAuth for a token probed under `host`, or
// ok=false on miss/expiry/host mismatch. This is the closure the HTTP
// listener calls for /.well-known/acme-challenge/<token>.
//
// The host check matters (audit finding CERT-1): this table is filled
// from a bus subject every platform edge subscribes to, so without it
// ANY live token is answered under ANY Host. Combined with an issuance
// path that did not check domain ownership, that let one org obtain a
// real certificate for another org's domain. An http-01 validator always
// probes the exact name it is validating, so binding the answer to the
// token's own domain costs nothing legitimate.
func (s *Store) Resolve(token, host string) (string, bool) {
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
	if e.domain == "" {
		// An older cert-svc published no domain. Answer (so an in-flight
		// issuance across a rollout still completes) but say so — once
		// both sides are current this should never appear.
		s.logger.Warn("acme challenge has no domain; answering without a host check",
			"token", token, "host", host)
		return e.keyAuth, true
	}
	if !hostMatches(host, e.domain) {
		s.logger.Warn("refusing acme challenge: probed under a host the token was not issued for",
			"token", token, "probed_host", host, "token_domain", e.domain)
		return "", false
	}
	return e.keyAuth, true
}

// hostMatches compares a request Host (which may carry a port) against the
// token's domain, case-insensitively.
func hostMatches(host, domain string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i+1:], ":") {
		if _, err := strconv.Atoi(h[i+1:]); err == nil {
			h = h[:i]
		}
	}
	return h == domain
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
