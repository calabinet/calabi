package store

import (
	"context"
	"fmt"
	"time"

	entsql "entgo.io/ent/dialect/sql"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
	"github.com/calabi/calabi/apps/calabi-coord/internal/platform/store/ent"
	"github.com/calabi/calabi/apps/calabi-coord/internal/platform/store/ent/meshauthkey"
	"github.com/calabi/calabi/apps/calabi-coord/internal/platform/store/ent/predicate"
)

// The auth keys a self-hosted coordinator mints (core.AuthKeyStore).

var _ core.AuthKeyStore = (*Store)(nil)

func (s *Store) CreateAuthKey(ctx context.Context, k *core.AuthKey) (*core.AuthKey, error) {
	tags, err := marshalStrings(k.Tags)
	if err != nil {
		return nil, err
	}
	c := s.client.MeshAuthKey.Create().
		SetMeshnetID(int64(k.Meshnet)).
		SetHash(k.Hash).
		SetPrefix(k.Prefix).
		SetTagsJSON(tags).
		SetMaxUses(k.MaxUses).
		SetUses(k.Uses).
		SetNote(k.Note)
	if !k.ExpiresAt.IsZero() {
		c.SetExpiresAt(k.ExpiresAt.UTC())
	}
	row, err := c.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("coord store: create auth key: %w", err)
	}
	return toAuthKey(row)
}

func (s *Store) AuthKeyByHash(ctx context.Context, hash string) (*core.AuthKey, error) {
	row, err := s.client.MeshAuthKey.Query().Where(meshauthkey.Hash(hash)).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, core.ErrAuthKeyNotFound
		}
		return nil, err
	}
	return toAuthKey(row)
}

func (s *Store) ListAuthKeys(ctx context.Context, meshnet core.MeshnetID) ([]*core.AuthKey, error) {
	rows, err := s.client.MeshAuthKey.Query().
		Where(meshauthkey.MeshnetID(int64(meshnet))).
		Order(ent.Desc(meshauthkey.FieldID)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*core.AuthKey, 0, len(rows))
	for _, r := range rows {
		k, err := toAuthKey(r)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}

func (s *Store) RevokeAuthKey(ctx context.Context, meshnet core.MeshnetID, id int64) error {
	n, err := s.client.MeshAuthKey.Update().
		Where(meshauthkey.ID(int(id)), meshauthkey.MeshnetID(int64(meshnet))).
		SetRevokedAt(time.Now().UTC()).
		Save(ctx)
	if err != nil {
		return err
	}
	if n == 0 {
		return core.ErrAuthKeyNotFound
	}
	return nil
}

// UseAuthKey counts a use in one conditional UPDATE, so two devices racing for
// the last use of a one-time key cannot both get it.
func (s *Store) UseAuthKey(ctx context.Context, id int64, now time.Time) error {
	n, err := s.client.MeshAuthKey.Update().
		Where(
			meshauthkey.ID(int(id)),
			meshauthkey.RevokedAtIsNil(),
			meshauthkey.Or(meshauthkey.ExpiresAtIsNil(), meshauthkey.ExpiresAtGT(now.UTC())),
			meshauthkey.Or(meshauthkey.MaxUses(0), predicate.MeshAuthKey(entsql.FieldsLT(meshauthkey.FieldUses, meshauthkey.FieldMaxUses))),
		).
		AddUses(1).
		Save(ctx)
	if err != nil {
		return err
	}
	if n == 1 {
		return nil
	}
	// Say which: an unknown key, or one that can no longer admit anyone.
	row, err := s.client.MeshAuthKey.Get(ctx, int(id))
	if err != nil {
		if ent.IsNotFound(err) {
			return core.ErrAuthKeyNotFound
		}
		return err
	}
	k, err := toAuthKey(row)
	if err != nil {
		return err
	}
	if uerr := k.Usable(now); uerr != nil {
		return uerr
	}
	return core.ErrAuthKeyUnusable
}

func (s *Store) UnuseAuthKey(ctx context.Context, id int64) error {
	_, err := s.client.MeshAuthKey.Update().
		Where(meshauthkey.ID(int(id)), meshauthkey.UsesGT(0)).
		AddUses(-1).
		Save(ctx)
	return err
}

func toAuthKey(r *ent.MeshAuthKey) (*core.AuthKey, error) {
	tags, err := unmarshalStrings(r.TagsJSON)
	if err != nil {
		return nil, fmt.Errorf("coord store: auth key %d tags: %w", r.ID, err)
	}
	k := &core.AuthKey{
		ID:        int64(r.ID),
		Meshnet:   core.MeshnetID(r.MeshnetID),
		Hash:      r.Hash,
		Prefix:    r.Prefix,
		Tags:      tags,
		MaxUses:   r.MaxUses,
		Uses:      r.Uses,
		Note:      r.Note,
		CreatedAt: r.CreatedAt,
	}
	if r.ExpiresAt != nil {
		k.ExpiresAt = *r.ExpiresAt
	}
	if r.RevokedAt != nil {
		k.RevokedAt = *r.RevokedAt
	}
	return k, nil
}
