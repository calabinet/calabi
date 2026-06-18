// health_source.go — bridges status.State (live tunnel snapshot) to
// probe.TunnelSource (input to the health monitor). Lives in cmd/ to
// avoid cross-import between internal/status and internal/probe.
package main

import (
	"github.com/calabi/calabi/apps/client/internal/probe"
	"github.com/calabi/calabi/apps/client/internal/status"
)

// stateSource adapts status.State for probe.Monitor.SetSource. The
// monitor calls LiveTunnels() each tick to discover what to probe.
type stateSource struct {
	state *status.State
}

func newStateSource(s *status.State) *stateSource { return &stateSource{state: s} }

// LiveTunnels snapshots the state's tunnel map. Pending tunnels are
// skipped — we can't probe what doesn't have a LocalAddr yet.
func (s *stateSource) LiveTunnels() []probe.TunnelTarget {
	snap := s.state.SnapshotNow()
	out := make([]probe.TunnelTarget, 0, len(snap.Tunnels))
	for _, t := range snap.Tunnels {
		if t.Pending || t.LocalAddr == "" {
			continue
		}
		out = append(out, probe.TunnelTarget{
			ProxyID:   t.ProxyID,
			Type:      t.Type,
			LocalAddr: t.LocalAddr,
		})
	}
	return out
}
