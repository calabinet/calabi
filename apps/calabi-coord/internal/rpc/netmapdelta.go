package rpc

import (
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"google.golang.org/protobuf/proto"
)

// One baseline per RPC stream, committed only when the frame was sent. No
// retained message history, no cross-session or cross-device delta reuse.
type deltaNetMapStream struct {
	meshpb.Coordinator_PullNetMapServer
	encoder      meshproto.NetMapEncoder
	wireSize     int
	delta        bool
	grantOnly    bool
	changed      <-chan struct{}
	fingerprints *meshproto.PeerFingerprintCache
}

func (s *deltaNetMapStream) Send(full *meshpb.NetMap) error {
	frame, next, err := s.encoder.NextWithPeerCache(full, s.fingerprints)
	if err != nil {
		return err
	}
	// Fingerprinting can take time for a large graph. Recheck immediately
	// before transport Send; a superseded frame must not advance the baseline.
	if mapChanged(s.changed) {
		return errMapSuperseded
	}
	if err = s.Coordinator_PullNetMapServer.Send(frame); err != nil {
		return err
	}
	s.encoder, s.wireSize = next, proto.Size(frame)
	s.delta, s.grantOnly = frame.Delta, frame.GrantOnly
	return nil
}

func (s *Server) recordMapFrame(stream meshpb.Coordinator_PullNetMapServer) {
	if d, ok := stream.(*deltaNetMapStream); ok && d.delta {
		if d.grantOnly {
			s.coord.Performance.GrantOnlyFrames.Add(1)
		} else {
			s.coord.Performance.DeltaFrames.Add(1)
		}
	} else {
		s.coord.Performance.FullFrames.Add(1)
	}
}

func netMapWireSize(s meshpb.Coordinator_PullNetMapServer, full *meshpb.NetMap) int {
	if delta, ok := s.(*deltaNetMapStream); ok {
		return delta.wireSize
	}
	return proto.Size(full)
}
