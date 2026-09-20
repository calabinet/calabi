package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
)

// The in-memory and the database key stores answer the same questions the same
// way; each case runs against both.
func TestAuthKeyStores(t *testing.T) {
	for name, mk := range map[string]func(t *testing.T) core.AuthKeyStore{
		"memory":   func(*testing.T) core.AuthKeyStore { return core.NewMemAuthKeyStore() },
		"database": func(t *testing.T) core.AuthKeyStore { return newTestStore(t) },
	} {
		t.Run(name, func(t *testing.T) { testAuthKeyStore(t, mk(t)) })
	}
}

func mint(t *testing.T, s core.AuthKeyStore, meshnet core.MeshnetID, edit func(*core.AuthKey)) (string, *core.AuthKey) {
	t.Helper()
	secret, k, err := core.NewAuthKey(meshnet)
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(k)
	}
	saved, err := s.CreateAuthKey(context.Background(), k)
	if err != nil {
		t.Fatal(err)
	}
	return secret, saved
}

func testAuthKeyStore(t *testing.T, s core.AuthKeyStore) {
	ctx := context.Background()
	now := time.Now()

	secret, one := mint(t, s, 1, func(k *core.AuthKey) { k.MaxUses, k.Tags, k.Note = 1, []string{"tag:phone"}, "alice" })
	if one.ID == 0 || one.CreatedAt.IsZero() {
		t.Fatalf("created key lacks id or time: %+v", one)
	}
	got, err := s.AuthKeyByHash(ctx, core.HashAuthKey(secret))
	if err != nil || got.ID != one.ID || got.Note != "alice" || len(got.Tags) != 1 || got.Tags[0] != "tag:phone" || got.MaxUses != 1 {
		t.Fatalf("by hash: %+v, %v", got, err)
	}
	if _, err := s.AuthKeyByHash(ctx, core.HashAuthKey("ck_nope")); !errors.Is(err, core.ErrAuthKeyNotFound) {
		t.Fatalf("unknown hash: %v", err)
	}

	// One use, then used up; taking a use back makes it usable again.
	if err := s.UseAuthKey(ctx, one.ID, now); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if err := s.UseAuthKey(ctx, one.ID, now); !errors.Is(err, core.ErrAuthKeyUnusable) {
		t.Fatalf("second use of a one-time key: %v", err)
	}
	if err := s.UnuseAuthKey(ctx, one.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.UseAuthKey(ctx, one.ID, now); err != nil {
		t.Fatalf("use after a refund: %v", err)
	}

	// Unlimited, expiring.
	_, open := mint(t, s, 1, func(k *core.AuthKey) { k.ExpiresAt = now.Add(time.Hour) })
	for i := 0; i < 3; i++ {
		if err := s.UseAuthKey(ctx, open.ID, now); err != nil {
			t.Fatalf("use %d of an unlimited key: %v", i+1, err)
		}
	}
	if err := s.UseAuthKey(ctx, open.ID, now.Add(2*time.Hour)); !errors.Is(err, core.ErrAuthKeyUnusable) {
		t.Fatalf("use after expiry: %v", err)
	}

	// Revoking is per meshnet, idempotent, and ends every use.
	if err := s.RevokeAuthKey(ctx, 2, open.ID); !errors.Is(err, core.ErrAuthKeyNotFound) {
		t.Fatalf("revoke from another meshnet: %v", err)
	}
	if err := s.RevokeAuthKey(ctx, 1, open.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeAuthKey(ctx, 1, open.ID); err != nil {
		t.Fatalf("revoking twice: %v", err)
	}
	if err := s.UseAuthKey(ctx, open.ID, now); !errors.Is(err, core.ErrAuthKeyUnusable) {
		t.Fatalf("use of a revoked key: %v", err)
	}
	if err := s.UseAuthKey(ctx, 9999, now); !errors.Is(err, core.ErrAuthKeyNotFound) {
		t.Fatalf("use of an unknown key: %v", err)
	}

	// Listed per meshnet, newest first, revoked included.
	mint(t, s, 2, nil)
	list, err := s.ListAuthKeys(ctx, 1)
	if err != nil || len(list) != 2 || list[0].ID != open.ID || list[1].ID != one.ID || list[0].RevokedAt.IsZero() {
		t.Fatalf("list meshnet 1: %+v, %v", list, err)
	}

	// The last use of a one-time key goes to exactly one of two racers.
	_, race := mint(t, s, 1, func(k *core.AuthKey) { k.MaxUses = 1 })
	var wg sync.WaitGroup
	var mu sync.Mutex
	won := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.UseAuthKey(ctx, race.ID, now) == nil {
				mu.Lock()
				won++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if won != 1 {
		t.Fatalf("%d racers got the one use", won)
	}
}
