package store

import (
	"context"
	"fmt"
	"time"

	entsql "entgo.io/ent/dialect/sql"

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	"github.com/calabinet/calabi/apps/calabi-coord/internal/platform/store/ent"
	"github.com/calabinet/calabi/apps/calabi-coord/internal/platform/store/ent/meshtunnel"
	"github.com/calabinet/calabi/apps/calabi-coord/internal/platform/store/ent/meshtunnelusage"
)

// Tunnels a self-hosted daemon reported, and their traffic (core/tunnels.go).

var (
	_ core.TunnelStore      = (*Store)(nil)
	_ core.TunnelUsageStore = (*Store)(nil)
)

// sumInt64 is SUM(field) AS as, cast back to a 64-bit integer: Postgres sums a
// bigint column into numeric, and what scans that into an int64 would then be up
// to the driver.
func sumInt64(field, as string) ent.AggregateFunc {
	return func(s *entsql.Selector) string {
		return entsql.As(fmt.Sprintf("CAST(SUM(%s) AS BIGINT)", s.C(field)), as)
	}
}

// ReplaceTunnels makes list the node's tunnels in one transaction: a name it
// reported before keeps its row (its id and first_seen), a new one is added, a
// name it no longer reports is deleted.
func (s *Store) ReplaceTunnels(ctx context.Context, t core.MeshnetID, nodeID int64, list []core.Tunnel, now time.Time) error {
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return fmt.Errorf("coord store: tunnels: %w", err)
	}
	if err := replaceTunnels(ctx, tx, t, nodeID, list, now); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("coord store: tunnels: commit: %w", err)
	}
	return nil
}

func replaceTunnels(ctx context.Context, tx *ent.Tx, t core.MeshnetID, nodeID int64, list []core.Tunnel, now time.Time) error {
	rows, err := tx.MeshTunnel.Query().Where(meshtunnel.NodeID(nodeID)).All(ctx)
	if err != nil {
		return fmt.Errorf("coord store: read tunnels: %w", err)
	}
	prev := make(map[string]*ent.MeshTunnel, len(rows))
	for _, r := range rows {
		prev[r.Name] = r
	}
	for _, tn := range list {
		if row, ok := prev[tn.Name]; ok {
			delete(prev, tn.Name)
			_, err = row.Update().
				SetMeshnetID(int64(t)).SetType(tn.Type).SetPublicAddr(tn.PublicAddr).SetLocalAddr(tn.LocalAddr).
				SetStatus(tn.Status).SetReportedAt(now).
				Save(ctx)
		} else {
			_, err = tx.MeshTunnel.Create().
				SetMeshnetID(int64(t)).SetNodeID(nodeID).SetName(tn.Name).
				SetType(tn.Type).SetPublicAddr(tn.PublicAddr).SetLocalAddr(tn.LocalAddr).
				SetStatus(tn.Status).SetFirstSeen(now).SetReportedAt(now).
				Save(ctx)
		}
		if err != nil {
			return fmt.Errorf("coord store: write tunnel %q: %w", tn.Name, err)
		}
	}
	for _, gone := range prev {
		if err := tx.MeshTunnel.DeleteOne(gone).Exec(ctx); err != nil {
			return fmt.Errorf("coord store: delete tunnel %q: %w", gone.Name, err)
		}
	}
	return nil
}

func (s *Store) ListTunnels(ctx context.Context, t core.MeshnetID) ([]core.Tunnel, error) {
	rows, err := s.client.MeshTunnel.Query().Where(meshtunnel.MeshnetID(int64(t))).All(ctx)
	if err != nil {
		return nil, fmt.Errorf("coord store: list tunnels: %w", err)
	}
	out := make([]core.Tunnel, 0, len(rows))
	for _, r := range rows {
		out = append(out, core.Tunnel{
			ID: int64(r.ID), Meshnet: core.MeshnetID(r.MeshnetID), NodeID: r.NodeID, Name: r.Name, Type: r.Type,
			PublicAddr: r.PublicAddr, LocalAddr: r.LocalAddr, Status: r.Status,
			FirstSeen: r.FirstSeen.UTC(), ReportedAt: r.ReportedAt.UTC(),
		})
	}
	return out, nil
}

func (s *Store) DeleteTunnelsOf(ctx context.Context, nodeID int64) error {
	if _, err := s.client.MeshTunnel.Delete().Where(meshtunnel.NodeID(nodeID)).Exec(ctx); err != nil {
		return fmt.Errorf("coord store: delete tunnels of node %d: %w", nodeID, err)
	}
	return nil
}

// AddTunnelUsage adds each row to its (node, name, hour) bucket. Read-modify-
// write, like the connection records (no sql/upsert in this build); a row that
// fails is skipped and the first error returned.
func (s *Store) AddTunnelUsage(ctx context.Context, rows []core.TunnelUsage) error {
	var firstErr error
	for _, r := range rows {
		if err := s.addTunnelUsage(ctx, r); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (s *Store) addTunnelUsage(ctx context.Context, r core.TunnelUsage) error {
	hour := r.Hour.UTC().Truncate(time.Hour)
	row, err := s.client.MeshTunnelUsage.Query().
		Where(meshtunnelusage.NodeID(r.NodeID), meshtunnelusage.Name(r.Name), meshtunnelusage.Hour(hour)).
		Only(ctx)
	switch {
	case ent.IsNotFound(err):
		_, err = s.client.MeshTunnelUsage.Create().
			SetMeshnetID(int64(r.Meshnet)).SetNodeID(r.NodeID).SetName(r.Name).SetHour(hour).
			SetBytesIn(r.BytesIn).SetBytesOut(r.BytesOut).
			Save(ctx)
	case err == nil:
		_, err = row.Update().AddBytesIn(r.BytesIn).AddBytesOut(r.BytesOut).Save(ctx)
	}
	if err != nil {
		return fmt.Errorf("coord store: tunnel usage: %w", err)
	}
	return nil
}

func (s *Store) TunnelBytesByHour(ctx context.Context, t core.MeshnetID, from, to time.Time) (map[time.Time]int64, error) {
	var rows []struct {
		Hour time.Time `json:"hour"`
		In   int64     `json:"bytes_in"`
		Out  int64     `json:"bytes_out"`
	}
	err := s.client.MeshTunnelUsage.Query().
		Where(
			meshtunnelusage.MeshnetID(int64(t)),
			meshtunnelusage.HourGTE(from.UTC()),
			meshtunnelusage.HourLT(to.UTC()),
		).
		GroupBy(meshtunnelusage.FieldHour).
		Aggregate(
			sumInt64(meshtunnelusage.FieldBytesIn, "bytes_in"),
			sumInt64(meshtunnelusage.FieldBytesOut, "bytes_out"),
		).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("coord store: tunnel bytes by hour: %w", err)
	}
	out := make(map[time.Time]int64, len(rows))
	for _, r := range rows {
		out[r.Hour.UTC()] += r.In + r.Out
	}
	return out, nil
}

func (s *Store) TunnelBytesSince(ctx context.Context, t core.MeshnetID, since time.Time) (map[core.TunnelKey]int64, error) {
	var rows []struct {
		NodeID int64  `json:"node_id"`
		Name   string `json:"name"`
		In     int64  `json:"bytes_in"`
		Out    int64  `json:"bytes_out"`
	}
	err := s.client.MeshTunnelUsage.Query().
		Where(meshtunnelusage.MeshnetID(int64(t)), meshtunnelusage.HourGTE(since.UTC().Truncate(time.Hour))).
		GroupBy(meshtunnelusage.FieldNodeID, meshtunnelusage.FieldName).
		Aggregate(
			sumInt64(meshtunnelusage.FieldBytesIn, "bytes_in"),
			sumInt64(meshtunnelusage.FieldBytesOut, "bytes_out"),
		).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("coord store: tunnel bytes since: %w", err)
	}
	out := make(map[core.TunnelKey]int64, len(rows))
	for _, r := range rows {
		out[core.TunnelKey{NodeID: r.NodeID, Name: r.Name}] = r.In + r.Out
	}
	return out, nil
}

func (s *Store) PurgeTunnelUsageBefore(ctx context.Context, cutoff time.Time) (int, error) {
	n, err := s.client.MeshTunnelUsage.Delete().Where(meshtunnelusage.HourLT(cutoff.UTC())).Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("coord store: purge tunnel usage: %w", err)
	}
	return n, nil
}
