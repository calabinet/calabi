package store

import (
	"context"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
	"github.com/calabi/calabi/apps/calabi-coord/internal/platform/store/ent"
	"github.com/calabi/calabi/apps/calabi-coord/internal/platform/store/ent/meshrelay"
)

// Self-hosted relay registry (R2). Every query here is scoped to one meshnet —
// an org's relay must appear only in that org's map, and the store is the last
// place that can be true.

func toRelay(row *ent.MeshRelay) core.Relay {
	return core.Relay{
		ID:        int64(row.ID),
		Meshnet:   core.MeshnetID(row.MeshnetID),
		Label:     row.Label,
		HostName:  row.HostName,
		DERPPort:  row.DerpPort,
		STUNPort:  row.StunPort,
		Enabled:   row.Enabled,
		CreatedAt: row.CreatedAt,
	}
}

// ListRelays returns a meshnet's registrations, oldest first.
func (s *Store) ListRelays(ctx context.Context, t core.MeshnetID) ([]core.Relay, error) {
	rows, err := s.client.MeshRelay.Query().
		Where(meshrelay.MeshnetID(int64(t))).
		Order(ent.Asc(meshrelay.FieldID)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]core.Relay, 0, len(rows))
	for _, row := range rows {
		out = append(out, toRelay(row))
	}
	return out, nil
}

// CreateRelay stores a registration. The (meshnet, label) unique index is the
// real guard against a duplicate: the coordinator checks first, but two
// concurrent registrations would both pass that check.
func (s *Store) CreateRelay(ctx context.Context, r core.Relay) (*core.Relay, error) {
	row, err := s.client.MeshRelay.Create().
		SetMeshnetID(int64(r.Meshnet)).
		SetLabel(r.Label).
		SetHostName(r.HostName).
		SetDerpPort(r.DERPPort).
		SetStunPort(r.STUNPort).
		SetEnabled(r.Enabled).
		Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, core.ErrRelayExists
		}
		return nil, err
	}
	out := toRelay(row)
	return &out, nil
}

// UpdateRelay rewrites the mutable fields. The label is NOT among them: it is
// the region code, and nodes report their home under it — renaming would orphan
// every node currently homed there.
func (s *Store) UpdateRelay(ctx context.Context, r core.Relay) error {
	_, err := s.client.MeshRelay.UpdateOneID(int(r.ID)).
		SetHostName(r.HostName).
		SetDerpPort(r.DERPPort).
		SetStunPort(r.STUNPort).
		SetEnabled(r.Enabled).
		Save(ctx)
	if ent.IsNotFound(err) {
		return core.ErrRelayNotFound
	}
	return err
}

// DeleteRelay removes a registration.
func (s *Store) DeleteRelay(ctx context.Context, id int64) error {
	err := s.client.MeshRelay.DeleteOneID(int(id)).Exec(ctx)
	if ent.IsNotFound(err) {
		return core.ErrRelayNotFound
	}
	return err
}
