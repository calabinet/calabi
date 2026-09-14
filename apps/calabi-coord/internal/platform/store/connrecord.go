package store

import (
	"context"
	"fmt"
	"time"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
	"github.com/calabi/calabi/apps/calabi-coord/internal/platform/store/ent"
	"github.com/calabi/calabi/apps/calabi-coord/internal/platform/store/ent/coordsetting"
	"github.com/calabi/calabi/apps/calabi-coord/internal/platform/store/ent/meshconnrecord"
)

// Connection records over ent — the data-plane audit trail (core/connrecord.go).

// AddConnSamples folds each record into its hourly bucket, ADDING to whatever is
// already stored for that (meshnet, src, dst, hour).
//
// Read-modify-write per row rather than an upsert: this project does not build
// ent with the sql/upsert feature, and the row count here is small by
// construction — a node reports only the peers it actually exchanged traffic
// with in the last few minutes, which for a normal fleet is a handful.
//
// A row that fails is skipped, not fatal. Losing one pair-hour of an
// observational trail is better than losing the whole report, and the caller has
// no useful retry: the samples are deltas, so a second attempt would double-
// count everything that did land.
func (s *Store) AddConnSamples(ctx context.Context, recs []core.ConnRecord) error {
	var firstErr error
	for _, r := range recs {
		if err := s.addOneConnRecord(ctx, r); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (s *Store) addOneConnRecord(ctx context.Context, r core.ConnRecord) error {
	hour := r.Hour.UTC().Truncate(time.Hour)
	row, err := s.client.MeshConnRecord.Query().
		Where(
			meshconnrecord.MeshnetID(int64(r.MeshnetID)),
			meshconnrecord.SrcNodeID(r.SrcNodeID),
			meshconnrecord.DstNodeID(r.DstNodeID),
			meshconnrecord.Hour(hour),
		).Only(ctx)
	switch {
	case ent.IsNotFound(err):
		create := s.client.MeshConnRecord.Create().
			SetMeshnetID(int64(r.MeshnetID)).
			SetSrcNodeID(r.SrcNodeID).
			SetDstNodeID(r.DstNodeID).
			SetHour(hour).
			SetBytesTx(r.BytesTx).
			SetBytesRx(r.BytesRx).
			SetPath(r.Path)
		if _, err := create.Save(ctx); err != nil {
			return fmt.Errorf("coord store: create conn record: %w", err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("coord store: read conn record: %w", err)
	}
	upd := row.Update().
		AddBytesTx(r.BytesTx).
		AddBytesRx(r.BytesRx)
	// Last one in the hour wins, and only when the node actually said something:
	// an empty path is "not reported", not "unknown path", and letting it clear a
	// good value would make the column flicker for no reason.
	if r.Path != "" {
		upd = upd.SetPath(r.Path)
	}
	if _, err := upd.Save(ctx); err != nil {
		return fmt.Errorf("coord store: add to conn record: %w", err)
	}
	return nil
}

// ListConnRecords returns a meshnet's rows in [from, to), newest hour first.
func (s *Store) ListConnRecords(ctx context.Context, t core.MeshnetID, from, to time.Time, limit int) ([]core.ConnRecord, error) {
	if limit <= 0 {
		limit = 500
	}
	q := s.client.MeshConnRecord.Query().
		Where(meshconnrecord.MeshnetID(int64(t)))
	if !from.IsZero() {
		q = q.Where(meshconnrecord.HourGTE(from.UTC()))
	}
	if !to.IsZero() {
		q = q.Where(meshconnrecord.HourLT(to.UTC()))
	}
	rows, err := q.
		Order(ent.Desc(meshconnrecord.FieldHour), ent.Asc(meshconnrecord.FieldID)).
		Limit(limit).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("coord store: list conn records: %w", err)
	}
	out := make([]core.ConnRecord, 0, len(rows))
	for _, m := range rows {
		out = append(out, core.ConnRecord{
			MeshnetID: core.MeshnetID(m.MeshnetID),
			SrcNodeID: m.SrcNodeID,
			DstNodeID: m.DstNodeID,
			Hour:      m.Hour.UTC(),
			BytesTx:   m.BytesTx,
			BytesRx:   m.BytesRx,
			Path:      m.Path,
		})
	}
	return out, nil
}

// PurgeConnRecordsBefore drops rows older than cutoff.
func (s *Store) PurgeConnRecordsBefore(ctx context.Context, cutoff time.Time) (int, error) {
	n, err := s.client.MeshConnRecord.Delete().
		Where(meshconnrecord.HourLT(cutoff.UTC())).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("coord store: purge conn records: %w", err)
	}
	return n, nil
}

// PurgeConnRecordsOf drops every row for one meshnet — what an org turning the
// trail off is asking for.
func (s *Store) PurgeConnRecordsOf(ctx context.Context, t core.MeshnetID) (int, error) {
	n, err := s.client.MeshConnRecord.Delete().
		Where(meshconnrecord.MeshnetID(int64(t))).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("coord store: purge conn records for meshnet %d: %w", t, err)
	}
	return n, nil
}

// --- platform settings (core.PlatformSettingStore) --------------------------

// GetSetting reads one operator-set value. Missing is not an error: the caller
// falls back to its default, which is the normal state before anyone has
// touched the console.
func (s *Store) GetSetting(ctx context.Context, key string) (string, bool, error) {
	row, err := s.client.CoordSetting.Query().
		Where(coordsetting.Key(key)).
		Only(ctx)
	if ent.IsNotFound(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("coord store: read setting %q: %w", key, err)
	}
	return row.Value, true, nil
}

// SetSetting writes one operator-set value, creating the row on first use.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	row, err := s.client.CoordSetting.Query().Where(coordsetting.Key(key)).Only(ctx)
	if ent.IsNotFound(err) {
		if _, cerr := s.client.CoordSetting.Create().SetKey(key).SetValue(value).Save(ctx); cerr != nil {
			return fmt.Errorf("coord store: create setting %q: %w", key, cerr)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("coord store: read setting %q: %w", key, err)
	}
	if _, err := row.Update().SetValue(value).Save(ctx); err != nil {
		return fmt.Errorf("coord store: write setting %q: %w", key, err)
	}
	return nil
}
