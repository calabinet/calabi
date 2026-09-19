package rpc

import (
	"errors"
	"testing"
	"time"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
)

func TestChallengeIsSingleUseAndBoundToItsMeshnet(t *testing.T) {
	s := newNodeSessions()
	id, _, err := s.issueChallenge(1)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, ok := s.takeChallenge(id, 2, 0); ok {
		t.Fatal("a challenge issued to meshnet 1 was accepted for meshnet 2")
	}
	// The failed attempt above burned it.
	if _, ok := s.takeChallenge(id, 1, 0); ok {
		t.Fatal("a challenge survived a failed use")
	}
	id2, _, _ := s.issueChallenge(1)
	if _, ok := s.takeChallenge(id2, 1, 0); !ok {
		t.Fatal("a fresh challenge was refused")
	}
	if _, ok := s.takeChallenge(id2, 1, 0); ok {
		t.Fatal("a challenge was accepted twice")
	}
}

func TestChallengeExpires(t *testing.T) {
	s := newNodeSessions()
	now := time.Unix(1_000_000, 0)
	s.now = func() time.Time { return now }
	id, _, _ := s.issueChallenge(1)
	now = now.Add(challengeTTL + time.Second)
	if _, ok := s.takeChallenge(id, 1, 0); ok {
		t.Fatal("an expired challenge was accepted")
	}
}

func TestPendingChallengesAreCapped(t *testing.T) {
	s := newNodeSessions()
	now := time.Unix(1_000_000, 0)
	s.now = func() time.Time { return now }

	// One meshnet fills its own share…
	for i := 0; i < maxPendingPerMeshnet; i++ {
		if _, _, err := s.issueChallenge(1); err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
	}
	if _, _, err := s.issueChallenge(1); !errors.Is(err, errTooManyChallenges) {
		t.Fatalf("err = %v, want errTooManyChallenges once the meshnet's share is full", err)
	}
	// …and that must not touch anyone else's (audit finding MESH-2).
	if _, _, err := s.issueChallenge(2); err != nil {
		t.Fatalf("a second meshnet was starved by the first: %v", err)
	}
	// Expiry frees the share again.
	now = now.Add(challengeTTL + time.Second)
	if _, _, err := s.issueChallenge(1); err != nil {
		t.Fatalf("expired challenges were not swept to make room: %v", err)
	}
}

func TestPendingChallengesGlobalCeiling(t *testing.T) {
	s := newNodeSessions()
	now := time.Unix(1_000_000, 0)
	s.now = func() time.Time { return now }

	// Enough distinct meshnets to reach the process-wide ceiling.
	issued := 0
	for m := 1; issued < maxPendingChallenges; m++ {
		for i := 0; i < maxPendingPerMeshnet; i++ {
			if _, _, err := s.issueChallenge(core.MeshnetID(m)); err != nil {
				t.Fatalf("issue (meshnet %d, %d): %v", m, i, err)
			}
			issued++
		}
	}
	if _, _, err := s.issueChallenge(core.MeshnetID(9999)); !errors.Is(err, errTooManyChallenges) {
		t.Fatalf("err = %v, want errTooManyChallenges at the global ceiling", err)
	}
}

// The per-meshnet counter must go back down as challenges are spent, or an org
// that enrolls maxPendingPerMeshnet devices could never enroll another.
func TestPendingChallengeCountReleasedOnUse(t *testing.T) {
	s := newNodeSessions()
	for i := 0; i < maxPendingPerMeshnet; i++ {
		id, _, err := s.issueChallenge(1)
		if err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
		if _, ok := s.takeChallenge(id, 1, 0); !ok {
			t.Fatalf("take %d: refused", i)
		}
	}
	if _, _, err := s.issueChallenge(1); err != nil {
		t.Fatalf("spent challenges did not release the meshnet's share: %v", err)
	}
}

func TestNewSessionSupersedesTheOld(t *testing.T) {
	s := newNodeSessions()
	n := &core.Node{ID: 7, Meshnet: 1}
	first, _ := s.start(n)
	second, _ := s.start(n)
	if _, ok := s.lookup(first); ok {
		t.Fatal("the superseded session is still valid")
	}
	if sess, ok := s.lookup(second); !ok || sess.nodeID != 7 {
		t.Fatalf("the new session = %+v, %v", sess, ok)
	}
}
