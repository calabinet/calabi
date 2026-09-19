package rpc

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
	meshpb "github.com/calabi/calabi/pkg/mesh-proto/meshpb"
)

// What a self-hosted coordinator serves its own apps: the tunnels its daemons
// report, their traffic, and a read-only session for a phone that is not
// connected. All of it answers
// PermissionDenied on a coordinator with an identity service behind it: there,
// tunnels, usage and who may see them are the platform's.

// notSelfHosted is the answer on a platform coordinator.
var notSelfHosted = status.Error(codes.PermissionDenied, "this is served by the platform API on this coordinator")

// authorizeReader returns the node a read-only call speaks for: the node of a
// live session, or of a view token from OpenViewSession.
func (s *Server) authorizeReader(ctx context.Context, token string) (*core.Node, error) {
	if token == "" {
		return nil, status.Error(codes.Unauthenticated, "session_token is required")
	}
	if _, ok := s.sessions.lookup(token); ok {
		return s.authorizeNode(ctx, token, 0)
	}
	view, ok := s.sessions.lookupView(token)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "unknown or expired session")
	}
	node, err := s.coord.Nodes.Get(ctx, view.nodeID)
	if err != nil {
		s.sessions.forgetView(token)
		if errors.Is(err, core.ErrNodeNotFound) {
			return nil, status.Error(codes.NotFound, "node not found")
		}
		return nil, status.Errorf(codes.Internal, "load node: %v", err)
	}
	switch {
	case node.Meshnet != view.meshnet || node.NodeKey != view.nodeKey:
		s.sessions.forgetView(token)
		return nil, status.Error(codes.Unauthenticated, "session no longer matches the node")
	case node.Disabled:
		s.sessions.forgetView(token)
		return nil, status.Error(codes.PermissionDenied, "node is disabled")
	case node.SignedOut:
		s.sessions.forgetView(token)
		return nil, status.Error(codes.FailedPrecondition, "node signed out")
	}
	return node, nil
}

// OpenViewSession issues a read-only token for a node that proves its key the
// way RegisterNode's re-registration does, without touching its live session,
// its presence or its record.
func (s *Server) OpenViewSession(ctx context.Context, req *meshpb.OpenViewSessionRequest) (*meshpb.OpenViewSessionResponse, error) {
	if !s.coord.SelfHosted() {
		return nil, notSelfHosted
	}
	node, err := s.reauthTarget(ctx, req.GetNodeId(), req.GetNodeKey())
	if err != nil {
		return nil, err
	}
	pending, ok := s.sessions.takeChallenge(req.GetChallengeId(), node.Meshnet, node.ID)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "challenge missing, expired or already used; call GetRegisterChallenge first")
	}
	if err := meshproto.OpenRegisterProof(pending.ch, pending.ephPriv, node.NodeKey, req.GetProof()); err != nil {
		return nil, status.Error(codes.Unauthenticated, "proof rejected: the caller does not hold this node key")
	}
	tok, exp, err := s.sessions.openView(node)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "view session: %v", err)
	}
	return &meshpb.OpenViewSessionResponse{ViewToken: tok, ExpiresUnix: exp.Unix()}, nil
}

// ReportTunnels records the tunnels the caller's daemon serves (core/tunnels.go).
// A view session will do: a device with its mesh switched off still serves
// tunnels, and reports them without joining the mesh.
func (s *Server) ReportTunnels(ctx context.Context, req *meshpb.ReportTunnelsRequest) (*meshpb.ReportTunnelsResponse, error) {
	if !s.coord.SelfHosted() {
		return nil, notSelfHosted
	}
	node, err := s.authorizeReader(ctx, req.GetSessionToken())
	if err != nil {
		return nil, err
	}
	reports := make([]core.TunnelReport, 0, len(req.GetTunnels()))
	for _, t := range req.GetTunnels() {
		reports = append(reports, core.TunnelReport{
			Name: t.GetName(), Type: t.GetType(), PublicAddr: t.GetPublicAddr(), LocalAddr: t.GetLocalAddr(),
			Status: t.GetStatus(), BytesIn: t.GetBytesIn(), BytesOut: t.GetBytesOut(),
		})
	}
	if err := s.coord.ReportTunnels(ctx, node, reports, time.Now()); err != nil {
		return nil, status.Errorf(codes.Internal, "report tunnels: %v", err)
	}
	return &meshpb.ReportTunnelsResponse{}, nil
}

// ListTunnels lists every tunnel the caller's meshnet reported.
func (s *Server) ListTunnels(ctx context.Context, req *meshpb.ListTunnelsRequest) (*meshpb.ListTunnelsResponse, error) {
	if !s.coord.SelfHosted() {
		return nil, notSelfHosted
	}
	self, err := s.authorizeReader(ctx, req.GetSessionToken())
	if err != nil {
		return nil, err
	}
	list, err := s.coord.MeshnetTunnels(ctx, self.Meshnet, time.Now())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list tunnels: %v", err)
	}
	out := &meshpb.ListTunnelsResponse{}
	for _, t := range list {
		out.Tunnels = append(out.Tunnels, &meshpb.TunnelInfo{
			Id: t.ID, NodeId: t.NodeID, NodeName: t.NodeName, NodeOnline: t.NodeOnline,
			Name: t.Name, Type: t.Type, PublicAddr: t.PublicAddr, LocalAddr: t.LocalAddr, Status: t.Status,
			Traffic_30D: t.Traffic30d, FirstSeenUnix: t.FirstSeen.Unix(), ReportedUnix: t.ReportedAt.Unix(),
		})
	}
	return out, nil
}

// GetUsage is the caller's meshnet's traffic through this server, in the
// viewer's time zone.
func (s *Server) GetUsage(ctx context.Context, req *meshpb.GetUsageRequest) (*meshpb.GetUsageResponse, error) {
	if !s.coord.SelfHosted() {
		return nil, notSelfHosted
	}
	self, err := s.authorizeReader(ctx, req.GetSessionToken())
	if err != nil {
		return nil, err
	}
	loc := time.UTC
	if tz := req.GetTimeZone(); tz != "" {
		if l, lerr := time.LoadLocation(tz); lerr == nil {
			loc = l
		}
	}
	days := int(req.GetDays())
	if days == 0 {
		days = 7
	}
	u, err := s.coord.Usage(ctx, self.Meshnet, loc, days, time.Now())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "usage: %v", err)
	}
	out := &meshpb.GetUsageResponse{
		Unavailable:      u.Unavailable,
		RelayNotRecorded: u.RelayNotRecorded,
		DevicesUsed:      int64(u.Seats.Active),
		DevicesDisabled:  int64(u.Seats.Disabled),
		DevicesLimit:     int64(u.Seats.Limit),
	}
	if u.Unavailable == "" {
		out.Month = &meshpb.UsageMonth{
			FromUnix: u.MonthFrom.Unix(), ToUnix: u.MonthTo.Unix(),
			TunnelBytes: u.MonthTunnel, RelayBytes: u.MonthRelay,
		}
		for _, d := range u.Days {
			out.Days = append(out.Days, &meshpb.UsageDay{StartUnix: d.Start.Unix(), Bytes: d.Bytes})
		}
	}
	return out, nil
}

// GetEdgeAccess tells the caller where to serve tunnels and hands it the grant
// the edge accepts (core/edgeaccess.go). A node waiting for approval gets
// nothing yet: an approval gate that let the device publish tunnels while it
// kept it out of the mesh would gate the smaller of the two.
func (s *Server) GetEdgeAccess(ctx context.Context, req *meshpb.GetEdgeAccessRequest) (*meshpb.GetEdgeAccessResponse, error) {
	if !s.coord.SelfHosted() {
		return nil, notSelfHosted
	}
	node, err := s.authorizeReader(ctx, req.GetSessionToken())
	if err != nil {
		return nil, err
	}
	if !node.Approved {
		return nil, status.Error(codes.FailedPrecondition, meshproto.AwaitingApproval)
	}
	edges, grant := s.coord.EdgeAccess(ctx, node)
	out := &meshpb.GetEdgeAccessResponse{Grant: grant}
	for _, e := range edges {
		out.Edges = append(out.Edges, &meshpb.EdgeInfo{Addr: e.Addr, Pin: e.Pin})
	}
	if len(grant) > 0 {
		if g, err := meshproto.ParseRelayGrant(grant); err == nil {
			out.GrantExpiresUnix = g.Expiry.Unix()
		}
	}
	return out, nil
}
