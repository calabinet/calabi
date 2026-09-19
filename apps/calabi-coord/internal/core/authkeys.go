package core

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Auth keys the coordinator mints itself — the invites of a self-hosted
// coordinator. A key-file entry
// is permanent and reusable; one of these can be one-time, can expire, and can
// be revoked without a restart. Only its hash is stored: the key is shown once,
// when it is created.
//
// A key admits a device. It does not stay attached to it: once enrolled, a
// device comes back by proof of its node key (node_reauth), so revoking or
// using up a key never removes a device it already admitted.
//
// Expiry and the use limit are about admitting NEW devices. A device the key
// already admitted may present it again — a desktop whose config file holds it
// does, after every restart — and is let through; Spend is not called for it.
// Only revoking a key stops that.

// AuthKeyPrefix starts every minted key, so one is recognisable in a config
// file or a support ticket, and so Resolve can tell it from a key-file entry
// without a lookup.
const AuthKeyPrefix = "ck_"

var (
	// ErrAuthKeyNotFound is an unknown key or id.
	ErrAuthKeyNotFound = errors.New("core: auth key not found")
	// ErrAuthKeyUnusable is a key that is revoked, expired or used up.
	ErrAuthKeyUnusable = errors.New("core: auth key revoked, expired or used up")
)

// AuthKey is one minted key, without the key itself.
type AuthKey struct {
	ID      int64
	Meshnet MeshnetID
	// Hash is HashAuthKey of the key; Prefix is its first characters, enough to
	// recognise it in a list.
	Hash   string
	Prefix string
	// Tags are stamped on every device it admits, as a key-file entry's are.
	Tags []string
	// MaxUses is how many devices it may admit; 0 = any number. Uses is how
	// many it has.
	MaxUses int
	Uses    int
	// ExpiresAt zero = never. RevokedAt zero = not revoked.
	ExpiresAt time.Time
	RevokedAt time.Time
	CreatedAt time.Time
	// Note is the operator's own label ("Alice's phone").
	Note string
}

// Usable reports why k cannot admit a device at now, or nil.
func (k *AuthKey) Usable(now time.Time) error {
	switch {
	case !k.RevokedAt.IsZero():
		return fmt.Errorf("%w: revoked", ErrAuthKeyUnusable)
	case !k.ExpiresAt.IsZero() && !now.Before(k.ExpiresAt):
		return fmt.Errorf("%w: expired", ErrAuthKeyUnusable)
	case k.MaxUses > 0 && k.Uses >= k.MaxUses:
		return fmt.Errorf("%w: used up", ErrAuthKeyUnusable)
	}
	return nil
}

// Principal is what a device admitted by k enrolled as (Node.EnrolledBy).
func (k *AuthKey) Principal() string { return authKeyPrincipal + strconv.FormatInt(k.ID, 10) }

const authKeyPrincipal = "authkey:"

// ListenerTLS describes the coordinator's gRPC listener: Mode is "files" (a
// certificate the operator configured), "self-signed" (one the coordinator
// generated and keeps) or "off" (plaintext); Pin is its certificate's
// fingerprint (meshproto.CertPin), "" when off.
type ListenerTLS struct {
	Mode string
	Pin  string
}

// AuthKeyStore keeps minted keys.
type AuthKeyStore interface {
	// CreateAuthKey stores k (ID 0) and returns it with its ID and CreatedAt.
	CreateAuthKey(ctx context.Context, k *AuthKey) (*AuthKey, error)
	// AuthKeyByHash returns the key with this hash, or ErrAuthKeyNotFound.
	AuthKeyByHash(ctx context.Context, hash string) (*AuthKey, error)
	// ListAuthKeys returns a meshnet's keys, newest first, revoked included.
	ListAuthKeys(ctx context.Context, meshnet MeshnetID) ([]*AuthKey, error)
	// RevokeAuthKey revokes one of a meshnet's keys; ErrAuthKeyNotFound when the
	// meshnet has no such key. Revoking twice is not an error.
	RevokeAuthKey(ctx context.Context, meshnet MeshnetID, id int64) error
	// UseAuthKey counts one use, atomically, and only if the key is still
	// usable at now; otherwise ErrAuthKeyUnusable (or ErrAuthKeyNotFound).
	UseAuthKey(ctx context.Context, id int64, now time.Time) error
	// UnuseAuthKey takes back a use counted for an enrollment that then
	// failed.
	UnuseAuthKey(ctx context.Context, id int64) error
}

// NewAuthKey mints a key: the secret, shown to the operator once, and the
// record that is kept.
func NewAuthKey(meshnet MeshnetID) (secret string, k *AuthKey, err error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", nil, err
	}
	secret = AuthKeyPrefix + base64.RawURLEncoding.EncodeToString(b[:])
	return secret, &AuthKey{Meshnet: meshnet, Hash: HashAuthKey(secret), Prefix: secret[:len(AuthKeyPrefix)+6]}, nil
}

// HashAuthKey is what is stored in place of a key.
func HashAuthKey(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// KeyAuth is a self-hosted coordinator's Authenticator: the operator's key file
// (Static, optional) and the keys the coordinator minted (Keys).
type KeyAuth struct {
	// Static resolves key-file entries; nil when there is no file.
	Static Authenticator
	Keys   AuthKeyStore
	// Now is time.Now; tests set it.
	Now func() time.Time
}

func (a *KeyAuth) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// Resolve tries the key file, then the minted keys. A revoked key is refused
// here; expiry and the use limit are checked by Spend, which runs only when the
// key admits a new device (see the note at the top of this file).
func (a *KeyAuth) Resolve(ctx context.Context, authKey string) (Identity, error) {
	if a.Static != nil {
		if id, err := a.Static.Resolve(ctx, authKey); err == nil {
			return id, nil
		}
	}
	if a.Keys == nil || !strings.HasPrefix(authKey, AuthKeyPrefix) {
		return Identity{}, ErrAuthDenied
	}
	k, err := a.Keys.AuthKeyByHash(ctx, HashAuthKey(authKey))
	if err != nil {
		return Identity{}, ErrAuthDenied
	}
	if !k.RevokedAt.IsZero() {
		return Identity{}, ErrAuthDenied
	}
	return Identity{Meshnet: k.Meshnet, Tags: slices.Clone(k.Tags), Principal: k.Principal()}, nil
}

// Reauthorize lets every enrolled node back in, as StaticAuth does: a key
// admits a device, and revoking the key does not remove it.
func (a *KeyAuth) Reauthorize(context.Context, MeshnetID, string) error { return nil }

// Spend counts a use of the minted key behind principal. Anything else — a
// key-file entry, the platform's credentials — has no uses to count.
func (a *KeyAuth) Spend(ctx context.Context, principal string) (func(), error) {
	idText, ok := strings.CutPrefix(principal, authKeyPrincipal)
	if !ok || a.Keys == nil {
		return func() {}, nil
	}
	id, err := strconv.ParseInt(idText, 10, 64)
	if err != nil {
		return nil, ErrAuthDenied
	}
	if err := a.Keys.UseAuthKey(ctx, id, a.now()); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAuthDenied, err)
	}
	return func() { _ = a.Keys.UnuseAuthKey(context.Background(), id) }, nil
}

// MemAuthKeyStore keeps minted keys in memory: a coordinator without a
// database, whose keys — like the rest of its state — go with a restart.
type MemAuthKeyStore struct {
	mu   sync.Mutex
	next int64
	keys map[int64]*AuthKey
}

func NewMemAuthKeyStore() *MemAuthKeyStore { return &MemAuthKeyStore{keys: map[int64]*AuthKey{}} }

func (s *MemAuthKeyStore) CreateAuthKey(_ context.Context, k *AuthKey) (*AuthKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	cp := *k
	cp.ID, cp.CreatedAt, cp.Tags = s.next, time.Now().UTC(), slices.Clone(k.Tags)
	s.keys[cp.ID] = &cp
	out := cp
	return &out, nil
}

func (s *MemAuthKeyStore) AuthKeyByHash(_ context.Context, hash string) (*AuthKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.keys {
		if k.Hash == hash {
			out := *k
			return &out, nil
		}
	}
	return nil, ErrAuthKeyNotFound
}

func (s *MemAuthKeyStore) ListAuthKeys(_ context.Context, meshnet MeshnetID) ([]*AuthKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*AuthKey
	for _, k := range s.keys {
		if k.Meshnet == meshnet {
			cp := *k
			out = append(out, &cp)
		}
	}
	slices.SortFunc(out, func(a, b *AuthKey) int { return int(b.ID - a.ID) })
	return out, nil
}

func (s *MemAuthKeyStore) RevokeAuthKey(_ context.Context, meshnet MeshnetID, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok || k.Meshnet != meshnet {
		return ErrAuthKeyNotFound
	}
	if k.RevokedAt.IsZero() {
		k.RevokedAt = time.Now().UTC()
	}
	return nil
}

func (s *MemAuthKeyStore) UseAuthKey(_ context.Context, id int64, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		return ErrAuthKeyNotFound
	}
	if err := k.Usable(now); err != nil {
		return err
	}
	k.Uses++
	return nil
}

func (s *MemAuthKeyStore) UnuseAuthKey(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if k, ok := s.keys[id]; ok && k.Uses > 0 {
		k.Uses--
	}
	return nil
}
