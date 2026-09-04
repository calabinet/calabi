// Package rpc adapts the mesh Coordinator gRPC contract (pkg/mesh-proto/meshpb)
// onto the edition-agnostic core. It owns auth (via core.Authenticator),
// core<->wire conversion, and the live netmap push loop (via core.Notifier).
package rpc

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
	meshpb "github.com/calabi/calabi/pkg/mesh-proto/meshpb"
)

// Server implements meshpb.CoordinatorServer.
type Server struct {
	meshpb.UnimplementedCoordinatorServer
	coord  *core.Coordinator
	auth   core.Authenticator
	notif  *core.Notifier
	logger *slog.Logger
}

// New builds the RPC server.
func New(coord *core.Coordinator, auth core.Authenticator, notif *core.Notifier, logger *slog.Logger) *Server {
	return &Server{coord: coord, auth: auth, notif: notif, logger: logger}
}

// UpdateNodeDeclarations records new declarations for a node that is ALREADY
// enrolled, without touching its session.
//
// Authenticated exactly like RegisterNode — the auth key resolves to a meshnet
// and node_key selects within it — so it grants nothing RegisterNode didn't
// already grant. What it avoids is the cost: re-enrolling to change a service
// list tore down the datapath and re-punched every path for an edit that moves
// no addresses.
//
// Peers still get bumped: declarations are ACL "svc:" selectors, so the
// coordinator recompiles each receiver's port filter from them.
func (s *Server) UpdateNodeDeclarations(ctx context.Context, req *meshpb.UpdateNodeDeclarationsRequest) (*meshpb.UpdateNodeDeclarationsResponse, error) {
	ident, err := s.auth.Resolve(ctx, req.GetAuthKey())
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "auth key denied")
	}
	nodeKey, err := meshproto.ParseNodeKey(req.GetNodeKey())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "node_key: %v", err)
	}
	in := core.UpdateDeclarationsInput{
		Meshnet:           ident.Meshnet,
		NodeKey:           nodeKey,
		DeviceFingerprint: req.GetDeviceFingerprint(),
	}
	for _, d := range req.GetDeclaredServices() {
		in.DeclaredServices = append(in.DeclaredServices, core.Service{
			Name: d.GetName(), Proto: d.GetProto(), Port: int(d.GetPort()),
			Target: d.GetTarget(), Note: d.GetNote(),
		})
	}
	node, err := s.coord.UpdateDeclarations(ctx, in)
	if err != nil {
		switch {
		case errors.Is(err, core.ErrNodeNotFound):
			// Not an error the caller should retry: it means "you aren't
			// enrolled here", and the answer is to enroll.
			return nil, status.Error(codes.FailedPrecondition, "node is not enrolled in this meshnet")
		case errors.Is(err, core.ErrNodeDisabled):
			return nil, status.Error(codes.PermissionDenied, err.Error())
		default:
			return nil, status.Errorf(codes.Internal, "update declarations: %v", err)
		}
	}
	s.notif.Bump(ident.Meshnet)
	return &meshpb.UpdateNodeDeclarationsResponse{NodeId: node.ID}, nil
}

// RegisterNode authenticates the node's auth key to a meshnet, allocates its
// overlay address, persists it, and notifies existing peers so they pick it up.
func (s *Server) RegisterNode(ctx context.Context, req *meshpb.RegisterNodeRequest) (*meshpb.RegisterNodeResponse, error) {
	ident, err := s.auth.Resolve(ctx, req.GetAuthKey())
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "auth key denied")
	}
	meshnet := ident.Meshnet
	nodeKey, err := meshproto.ParseNodeKey(req.GetNodeKey())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "node_key: %v", err)
	}
	in := core.RegisterInput{
		Meshnet:           meshnet,
		Name:              req.GetName(),
		NodeKey:           nodeKey,
		Tags:              ident.Tags,
		OwnerUserID:       ident.UserID,
		DeviceFingerprint: req.GetDeviceFingerprint(),
	}
	// Declarations are claims: core records them as pending and an admin
	// confirms them. Nothing is validated here beyond shape — core drops the
	// unusable entries so one bad config line can't refuse the enrollment.
	for _, d := range req.GetDeclaredServices() {
		in.DeclaredServices = append(in.DeclaredServices, core.Service{
			Name: d.GetName(), Proto: d.GetProto(), Port: int(d.GetPort()),
			Target: d.GetTarget(), Note: d.GetNote(),
		})
	}
	// disco_key is optional in v0 (hole punching lands in MESH.4); accept empty.
	if dk := req.GetDiscoKey(); dk != "" {
		discoKey, err := meshproto.ParseDiscoKey(dk)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "disco_key: %v", err)
		}
		in.DiscoKey = discoKey
	}
	for _, raw := range req.GetAdvertisedRoutes() {
		pfx, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "advertised_route %q: %v", raw, err)
		}
		in.AdvertisedRoutes = append(in.AdvertisedRoutes, pfx.Masked())
	}

	node, err := s.coord.Register(ctx, in)
	if err != nil {
		switch {
		case errors.Is(err, core.ErrNodeQuotaExceeded):
			return nil, status.Error(codes.ResourceExhausted, err.Error())
		case errors.Is(err, core.ErrNodeDisabled):
			return nil, status.Error(codes.PermissionDenied, err.Error())
		default:
			return nil, status.Errorf(codes.Internal, "register: %v", err)
		}
	}

	// Peers in this meshnet should learn about the newcomer.
	s.notif.Bump(meshnet)

	ver, caps := negotiate(req.GetProtocolVersion(), req.GetCapabilities())
	return &meshpb.RegisterNodeResponse{
		NodeId:          node.ID,
		OverlayAddr:     node.Overlay.String(),
		ProtocolVersion: ver,
		Capabilities:    caps,
	}, nil
}

// PullNetMap streams the node's netmap: an initial snapshot, then a fresh one
// every time its meshnet changes, until the client disconnects.
//
// MESH.1 SIMPLIFICATION: the stream is keyed by node_id alone (no per-stream
// auth token yet). A real deployment must bind the stream to the node's
// authenticated identity — added alongside the ACL work (MESH.5).
func (s *Server) PullNetMap(req *meshpb.PullNetMapRequest, stream meshpb.Coordinator_PullNetMapServer) error {
	ctx := stream.Context()
	self, err := s.coord.Nodes.Get(ctx, req.GetNodeId())
	if err != nil {
		if errors.Is(err, core.ErrNodeNotFound) {
			return status.Error(codes.NotFound, "node not found")
		}
		return status.Errorf(codes.Internal, "load node: %v", err)
	}

	// The netmap stream is the node's live control connection: hold it open =
	// online, close it (client quit / network drop) = offline. Presence powers the
	// console's online/offline indicator, distinct from the admin Disabled flag.
	defer s.coord.Presence.Connected(self.ID)()

	sig, unsub := s.notif.Subscribe(self.Meshnet, self.ID)
	defer unsub()

	// Initial snapshot.
	if err := s.sendNetMap(stream, self.ID); err != nil {
		return err
	}
	// The netmap is otherwise event-driven, which is not enough once it carries a
	// RELAY GRANT (R0'): grants expire, and a meshnet where nothing changes would
	// let every node's authorization lapse and drop it off the relays. So re-send
	// on a timer as well. The tick is well under the grant's TTL, so a missed one
	// costs a retry rather than an outage.
	refresh := time.NewTicker(core.RelayGrantRefresh)
	defer refresh.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-sig:
			if err := s.sendNetMap(stream, self.ID); err != nil {
				return err
			}
		case <-refresh.C:
			if err := s.sendNetMap(stream, self.ID); err != nil {
				return err
			}
		}
	}
}

func (s *Server) sendNetMap(stream meshpb.Coordinator_PullNetMapServer, nodeID int64) error {
	nm, err := s.coord.NetMapFor(stream.Context(), nodeID)
	if err != nil {
		// An admin disable (MESH.8b) fires a notify; recomputing the map then
		// returns ErrNodeDisabled. Terminate the stream so the disabled node is
		// cut immediately, not just dropped from peers' maps.
		if errors.Is(err, core.ErrNodeDisabled) {
			return status.Error(codes.PermissionDenied, "node is disabled")
		}
		return status.Errorf(codes.Internal, "compute netmap: %v", err)
	}
	return stream.Send(toProtoNetMap(nm))
}

// ReportServiceHealth records what a node observes about its own services.
//
// Observation, not configuration: nothing here grants anything, so a node
// reporting nonsense costs it a wrong badge on its own row and nothing else.
// That is why it needs no approval step, unlike everything a node DECLARES.
func (s *Server) ReportServiceHealth(ctx context.Context, req *meshpb.ReportServiceHealthRequest) (*meshpb.ReportServiceHealthResponse, error) {
	self, err := s.coord.Nodes.Get(ctx, req.GetNodeId())
	if err != nil {
		if errors.Is(err, core.ErrNodeNotFound) {
			return nil, status.Error(codes.NotFound, "node not found")
		}
		return nil, status.Errorf(codes.Internal, "load node: %v", err)
	}
	out := make(map[string]core.ServiceHealth, len(req.GetServices()))
	for _, h := range req.GetServices() {
		if h.GetName() == "" || !h.GetChecked() {
			// Unchecked entries are dropped rather than stored as failures:
			// "could not test" and "does not work" look identical in a badge and
			// mean opposite things to whoever reads it.
			continue
		}
		out[h.GetName()] = core.ServiceHealth{TargetOK: h.GetTargetOk(), MeshOK: h.GetMeshOk()}
	}
	s.coord.ServiceHealth.Report(self.ID, out, time.Now())
	return &meshpb.ReportServiceHealthResponse{}, nil
}

// ReportEndpoints records a node's discovered candidate endpoints and notifies
// its peers so they can attempt direct paths (used from MESH.4).
func (s *Server) ReportEndpoints(ctx context.Context, req *meshpb.ReportEndpointsRequest) (*meshpb.ReportEndpointsResponse, error) {
	self, err := s.coord.Nodes.Get(ctx, req.GetNodeId())
	if err != nil {
		if errors.Is(err, core.ErrNodeNotFound) {
			return nil, status.Error(codes.NotFound, "node not found")
		}
		return nil, status.Errorf(codes.Internal, "load node: %v", err)
	}
	eps := make([]netip.AddrPort, 0, len(req.GetEndpoints()))
	for _, raw := range req.GetEndpoints() {
		ap, err := netip.ParseAddrPort(raw)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "endpoint %q: %v", raw, err)
		}
		eps = append(eps, ap)
	}
	if err := s.coord.Nodes.UpdateEndpoints(ctx, self.ID, eps); err != nil {
		return nil, status.Errorf(codes.Internal, "update endpoints: %v", err)
	}
	// The node also reports the relay region it measured as closest (MESH.4 B2b).
	// Only a region this coordinator published is accepted; a bad one is the
	// node's bug, not a reason to lose the endpoints it just reported, so the
	// endpoint update above stands either way.
	if _, err := s.coord.SetDERPHome(ctx, self.ID, req.GetHomeRegion()); err != nil {
		if errors.Is(err, core.ErrUnknownDERPRegion) {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "update derp home: %v", err)
	}
	s.notif.Bump(self.Meshnet)
	return &meshpb.ReportEndpointsResponse{}, nil
}

// negotiate returns the working protocol version + capability subset: the min of
// what the client and this coordinator support. v0 defines no capabilities.
func negotiate(clientVer uint32, _ []string) (uint32, []string) {
	ver := clientVer
	if ver > meshproto.ProtocolVersion {
		ver = meshproto.ProtocolVersion
	}
	return ver, nil
}
