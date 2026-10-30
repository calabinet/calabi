package rpc

import (
	"errors"
	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	"time"

	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// All modes, including legacy rollback, must leave a stalled Send when their
// subscription context ends. Never launch the next Send on this RPC while the
// old transport call is still running: end the RPC so gRPC cancels it instead.
func (s *Server) sendNetMapPayload(stream meshpb.Coordinator_PullNetMapServer, out *meshpb.NetMap, changed <-chan struct{}) error {
	ctx := stream.Context()
	done := make(chan error, 1)
	started := time.Now()
	defer s.coord.Performance.Stages.Observe(core.MapSend, started)
	if d, ok := stream.(*deltaNetMapStream); ok {
		d.changed = changed
	}
	go func() {
		if mapChanged(changed) {
			done <- errMapSuperseded
			return
		}
		done <- stream.Send(out)
	}()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	var err error
	select {
	case err = <-done:
	case <-changed:
		err = status.Error(codes.Aborted, "netmap changed during send; reconnect for current snapshot")
	case <-ctx.Done():
		err = ctx.Err()
	case <-timer.C:
		err = status.Error(codes.DeadlineExceeded, "netmap receiver stalled")
	}
	if errors.Is(err, errMapSuperseded) {
		return err
	}
	s.coord.Performance.SendNanos.Add(uint64(time.Since(started)))
	if err != nil {
		s.coord.Performance.SendFailures.Add(1)
	} else {
		s.coord.Performance.SentBytes.Add(uint64(netMapWireSize(stream, out)))
		s.coord.Performance.SentMaps.Add(1)
		s.recordMapFrame(stream)
	}
	return err
}
