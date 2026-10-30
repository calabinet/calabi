package core

import (
	"sync/atomic"
	"time"
)

// Performance contains only process-wide aggregates. No device or organization
// labels, authorization decisions, or packet bodies are retained here.
type Performance struct {
	Stages          StageTimings
	Builds          atomic.Uint64
	BuildFailures   atomic.Uint64
	BuildNanos      atomic.Uint64
	BuiltPeers      atomic.Uint64
	NodeGets        atomic.Uint64
	NodeLists       atomic.Uint64
	NodesListed     atomic.Uint64
	Streams         atomic.Int64
	SentMaps        atomic.Uint64
	SentBytes       atomic.Uint64
	SendFailures    atomic.Uint64
	SendNanos       atomic.Uint64
	InitialMaps     atomic.Uint64
	ChangedMaps     atomic.Uint64
	GrantMaps       atomic.Uint64
	SnapshotLoads   atomic.Uint64
	SnapshotHits    atomic.Uint64
	StaleMaps       atomic.Uint64
	BuildActive     atomic.Int64
	BuildPeak       atomic.Int64
	FullFrames      atomic.Uint64
	DeltaFrames     atomic.Uint64
	GrantOnlyFrames atomic.Uint64
}

type PerformanceSnapshot struct {
	Builds            uint64 `json:"builds"`
	BuildFailures     uint64 `json:"build_failures"`
	BuildMicros       uint64 `json:"build_micros"`
	BuiltPeers        uint64 `json:"built_peers"`
	NodeGets          uint64 `json:"node_gets"`
	NodeLists         uint64 `json:"node_lists"`
	NodesListed       uint64 `json:"nodes_listed"`
	Streams           int64  `json:"streams"`
	SentMaps          uint64 `json:"sent_maps"`
	SentProtobufBytes uint64 `json:"sent_protobuf_bytes"`
	SendFailures      uint64 `json:"send_failures"`
	SendMicros        uint64 `json:"send_micros"`
	InitialMaps       uint64 `json:"initial_maps"`
	ChangedMaps       uint64 `json:"changed_maps"`
	GrantMaps         uint64 `json:"grant_maps"`
	SnapshotLoads     uint64 `json:"snapshot_loads"`
	SnapshotHits      uint64 `json:"snapshot_hits"`
	StaleMaps         uint64 `json:"stale_maps"`
	BuildActive       int64  `json:"build_active"`
	BuildPeak         int64  `json:"build_peak"`
	FullFrames        uint64 `json:"full_frames"`
	DeltaFrames       uint64 `json:"delta_frames"`
	GrantOnlyFrames   uint64 `json:"grant_only_frames"`
}

func (p *Performance) Snapshot() PerformanceSnapshot {
	return PerformanceSnapshot{p.Builds.Load(), p.BuildFailures.Load(), p.BuildNanos.Load() / uint64(time.Microsecond), p.BuiltPeers.Load(), p.NodeGets.Load(), p.NodeLists.Load(), p.NodesListed.Load(), p.Streams.Load(), p.SentMaps.Load(), p.SentBytes.Load(), p.SendFailures.Load(), p.SendNanos.Load() / uint64(time.Microsecond), p.InitialMaps.Load(), p.ChangedMaps.Load(), p.GrantMaps.Load(), p.SnapshotLoads.Load(), p.SnapshotHits.Load(), p.StaleMaps.Load(), p.BuildActive.Load(), p.BuildPeak.Load(), p.FullFrames.Load(), p.DeltaFrames.Load(), p.GrantOnlyFrames.Load()}
}
