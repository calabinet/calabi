package core

import (
	"sync/atomic"
	"time"
)

// StageTimings retains bounded process aggregates, never identities or queries.
type StageTimings struct {
	values [11]stageTiming
}

type Stage int

const (
	RegisterWait Stage = iota
	RegisterHeld
	RegisterPeers
	RegisterFind
	RegisterWrite
	RegisterServices
	SnapshotRead
	MapQueue
	MapSend
	IdentityCheck
	SnapshotSchedule
)

var stageNames = [...]string{"register_wait", "register_held", "register_peers", "register_find", "register_write", "register_services", "snapshot_read", "map_queue", "map_send", "identity_check", "snapshot_schedule"}

type stageTiming struct{ count, nanos, max atomic.Uint64 }
type StageTimingSnapshot struct {
	Count     uint64  `json:"count"`
	Millis    float64 `json:"total_ms"`
	MaxMillis float64 `json:"max_ms"`
}

func (s *StageTimings) Observe(stage Stage, started time.Time) {
	n := uint64(time.Since(started))
	v := &s.values[stage]
	v.count.Add(1)
	v.nanos.Add(n)
	for old := v.max.Load(); n > old; old = v.max.Load() {
		if v.max.CompareAndSwap(old, n) {
			break
		}
	}
}

func (s *StageTimings) Snapshot() map[string]StageTimingSnapshot {
	out := make(map[string]StageTimingSnapshot, len(stageNames))
	for i, name := range stageNames {
		v := &s.values[i]
		out[name] = StageTimingSnapshot{v.count.Load(), float64(v.nanos.Load()) / 1e6, float64(v.max.Load()) / 1e6}
	}
	return out
}

// Reset is used at quiescent fixture phase boundaries only.
func (s *StageTimings) Reset() {
	for i := range s.values {
		v := &s.values[i]
		v.count.Store(0)
		v.nanos.Store(0)
		v.max.Store(0)
	}
}
