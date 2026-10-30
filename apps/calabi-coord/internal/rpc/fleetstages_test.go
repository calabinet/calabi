package rpc

import (
	"context"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

// Only method/status categories are retained, never credentials or error bodies.
type fleetRPCStats struct {
	mu   sync.Mutex
	rows map[string]fleetRPCStage
}
type fleetRPCStage struct {
	Count     int     `json:"count"`
	Millis    float64 `json:"total_ms"`
	MaxMillis float64 `json:"max_ms"`
}

func (s *fleetRPCStats) record(method string, start time.Time, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rows == nil {
		s.rows = map[string]fleetRPCStage{}
	}
	key := method[strings.LastIndex(method, "/")+1:] + "/" + status.Code(err).String()
	if status.Convert(err).Message() == "netmap receiver stalled" {
		key += "/send_timeout"
	}
	if status.Convert(err).Message() == "netmap changed during send; reconnect for current snapshot" {
		key += "/map_changed_during_send"
	}
	v := s.rows[key]
	ms := float64(time.Since(start)) / float64(time.Millisecond)
	v.Count++
	v.Millis += ms
	v.MaxMillis = max(v.MaxMillis, ms)
	s.rows[key] = v
}
func (s *fleetRPCStats) unary(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
	start := time.Now()
	out, err := next(ctx, req)
	s.record(info.FullMethod, start, err)
	return out, err
}
func (s *fleetRPCStats) stream(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, next grpc.StreamHandler) error {
	start := time.Now()
	err := next(srv, stream)
	s.record(info.FullMethod, start, err)
	return err
}
func (s *fleetRPCStats) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows = map[string]fleetRPCStage{}
}
func (s *fleetRPCStats) snapshot() map[string]fleetRPCStage {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]fleetRPCStage{}
	for k, v := range s.rows {
		out[k] = v
	}
	return out
}
