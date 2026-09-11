package rpc

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// Node sessions (mesh protocol v2).
//
// An org credential names a meshnet, not a device, so it cannot be what says "I
// am node 42": with only that, any member could present their own key with a
// colleague's node key and be treated as that device (security audit 1-C,
// same-org residual). Identity now comes from the node private key, proven ONCE
// per session at registration against a one-time challenge. The coordinator then
// hands back a session token, and that token - not an org key - is what the
// node-scoped calls are authorized by.
//
// Both tables live in memory. A coordinator restart forgets every session, which
// costs nothing extra: a restart also ends every netmap stream, and a node whose
// stream ends re-registers - and so proves itself again - before it does anything
// else. This does assume ONE coordinator process; replicas would need a shared
// store or sticky routing for both tables.

const (
	// challengeTTL bounds the gap between asking for a challenge and answering it.
	// A node makes the two calls back to back.
	challengeTTL = 30 * time.Second
	// maxPendingChallenges caps the state a caller can make the coordinator hold.
	// Expired entries are swept before a new challenge is refused.
	maxPendingChallenges = 4096
	// maxPendingPerMeshnet caps how much of that table ONE org may hold.
	//
	// Without it the global cap was a cross-tenant weapon (audit finding
	// MESH-2): any account could ask for 4096 challenges, never answer them, and
	// every other org's registration failed until they expired — refilled every
	// 30 seconds for as long as the attacker cared to. Since v2 made
	// registration the only way to get a session, and nodes re-register whenever
	// a stream drops, that is the whole platform's mesh held down.
	//
	// A real fleet asks for one challenge per device and answers it immediately,
	// so this only has to cover honest concurrency, not fleet size.
	maxPendingPerMeshnet = 64
)

var errTooManyChallenges = errors.New("too many pending registration challenges; retry shortly")

type pendingChallenge struct {
	ch      meshproto.RegisterChallenge
	ephPriv [meshproto.KeyLen]byte
	meshnet core.MeshnetID
	expires time.Time
}

type nodeSession struct {
	nodeID  int64
	meshnet core.MeshnetID
	nodeKey meshproto.NodeKey
}

type nodeSessions struct {
	mu      sync.Mutex
	now     func() time.Time
	pending map[string]pendingChallenge // challenge id -> challenge
	// perMeshnet counts live entries in pending by meshnet, so one org's share
	// can be capped without scanning the table on every call.
	perMeshnet map[core.MeshnetID]int
	byToken    map[string]nodeSession // session token -> node
	byNode     map[int64]string       // node id -> its one live token
}

func newNodeSessions() *nodeSessions {
	return &nodeSessions{
		now:        time.Now,
		pending:    map[string]pendingChallenge{},
		perMeshnet: map[core.MeshnetID]int{},
		byToken:    map[string]nodeSession{},
		byNode:     map[int64]string{},
	}
}

// dropPending removes one pending challenge and keeps the per-meshnet count in
// step. Caller holds the lock.
func (s *nodeSessions) dropPending(id string) {
	p, ok := s.pending[id]
	if !ok {
		return
	}
	delete(s.pending, id)
	if n := s.perMeshnet[p.meshnet] - 1; n > 0 {
		s.perMeshnet[p.meshnet] = n
	} else {
		delete(s.perMeshnet, p.meshnet)
	}
}

// sweepExpired drops every challenge past its TTL. Caller holds the lock.
func (s *nodeSessions) sweepExpired(now time.Time) {
	for k, p := range s.pending {
		if now.After(p.expires) {
			s.dropPending(k)
		}
	}
}

// issueChallenge creates a one-time challenge bound to the meshnet the caller
// authenticated to, so a challenge obtained with one org's key cannot be spent
// enrolling into another.
func (s *nodeSessions) issueChallenge(meshnet core.MeshnetID) (string, meshproto.RegisterChallenge, error) {
	ch, ephPriv, err := meshproto.NewRegisterChallenge()
	if err != nil {
		return "", ch, err
	}
	id, err := randomToken()
	if err != nil {
		return "", ch, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	// Sweep first when either ceiling is in reach; an expired entry holds no
	// one's slot.
	if len(s.pending) >= maxPendingChallenges || s.perMeshnet[meshnet] >= maxPendingPerMeshnet {
		s.sweepExpired(now)
	}
	// Per-meshnet BEFORE global: one org running out of its own share must not
	// read as the platform being out of room, and must not be able to make it so.
	if s.perMeshnet[meshnet] >= maxPendingPerMeshnet {
		return "", ch, errTooManyChallenges
	}
	if len(s.pending) >= maxPendingChallenges {
		return "", ch, errTooManyChallenges
	}
	s.pending[id] = pendingChallenge{ch: ch, ephPriv: ephPriv, meshnet: meshnet, expires: now.Add(challengeTTL)}
	s.perMeshnet[meshnet]++
	return id, ch, nil
}

// takeChallenge removes and returns a challenge. Single use: it is gone whether
// or not the proof that follows checks out, so a failed attempt cannot be retried
// against the same challenge.
func (s *nodeSessions) takeChallenge(id string, meshnet core.MeshnetID) (pendingChallenge, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[id]
	if !ok {
		return pendingChallenge{}, false
	}
	s.dropPending(id)
	if s.now().After(p.expires) || p.meshnet != meshnet {
		return pendingChallenge{}, false
	}
	return p, true
}

// start opens a session for a node that has just proved itself and returns its
// token. The node's previous session, if any, ends: one live session per node.
func (s *nodeSessions) start(node *core.Node) (string, error) {
	tok, err := randomToken()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.byNode[node.ID]; ok {
		delete(s.byToken, old)
	}
	s.byToken[tok] = nodeSession{nodeID: node.ID, meshnet: node.Meshnet, nodeKey: node.NodeKey}
	s.byNode[node.ID] = tok
	return tok, nil
}

func (s *nodeSessions) lookup(tok string) (nodeSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byToken[tok]
	return sess, ok
}

// forget drops a session whose node no longer matches it (deleted, or replaced).
func (s *nodeSessions) forget(tok string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.byToken[tok]; ok {
		delete(s.byToken, tok)
		if s.byNode[sess.nodeID] == tok {
			delete(s.byNode, sess.nodeID)
		}
	}
}

func randomToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
