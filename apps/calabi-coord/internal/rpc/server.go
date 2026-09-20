// Package rpc adapts the mesh Coordinator gRPC contract (pkg/mesh-proto/meshpb)
// onto the deployment-agnostic core. It owns auth (via core.Authenticator),
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

	"github.com/calabinet/calabi/apps/calabi-coord/internal/core"
	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	meshpb "github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
)

// Server implements meshpb.CoordinatorServer.
type Server struct {
	meshpb.UnimplementedCoordinatorServer
	coord  *core.Coordinator
	auth   core.Authenticator
	notif  *core.Notifier
	logger *slog.Logger
	// sessions holds registration challenges and node sessions (mesh protocol
	// v2, nodeauth.go).
	sessions *nodeSessions
}

// New builds the RPC server.
func New(coord *core.Coordinator, auth core.Authenticator, notif *core.Notifier, logger *slog.Logger) *Server {
	return &Server{coord: coord, auth: auth, notif: notif, logger: logger, sessions: newNodeSessions()}
}

// minNodeProtocolVersion is the oldest mesh protocol a node may enroll with.
// v2 (2026-09-10) is where registration started proving possession of the node
// private key and the node-scoped calls started carrying the session that proof
// earns (nodeauth.go). A node below it can do neither.
const minNodeProtocolVersion uint32 = 2

// authorizeNode returns the node a session token speaks for, refusing the call
// when the token belongs to a different node than the request names. nodeID 0
// means the request names none (UpdateNodeDeclarations): the session decides.
//
// PullNetMap, ReportEndpoints and ReportServiceHealth used to trust node_id
// alone - sequential ids on an internet-facing listener, so anyone could read
// any org's netmap or rewrite any node (security audit 1-C). An org key plus a
// node key was not enough either: node keys are public within an org, so any
// member could speak for a colleague's device. A session exists only for a node
// that proved it holds its private key at registration.
func (s *Server) authorizeNode(ctx context.Context, token string, nodeID int64) (*core.Node, error) {
	if token == "" {
		return nil, status.Error(codes.Unauthenticated, "session_token is required")
	}
	sess, ok := s.sessions.lookup(token)
	if !ok {
		// Unknown to THIS process: never issued, superseded by a newer
		// registration, or issued before a restart. Registering again fixes all
		// three, and is what a node does when its stream ends.
		return nil, status.Error(codes.Unauthenticated, "unknown session; register again")
	}
	if nodeID != 0 && sess.nodeID != nodeID {
		return nil, status.Error(codes.PermissionDenied, "session belongs to a different node")
	}
	node, err := s.coord.Nodes.Get(ctx, sess.nodeID)
	if err != nil {
		if errors.Is(err, core.ErrNodeNotFound) {
			s.sessions.forget(token)
			return nil, status.Error(codes.NotFound, "node not found")
		}
		return nil, status.Errorf(codes.Internal, "load node: %v", err)
	}
	// The session was minted for this exact row; if the row no longer matches,
	// the session is stale.
	if node.Meshnet != sess.meshnet || node.NodeKey != sess.nodeKey {
		s.sessions.forget(token)
		return nil, status.Error(codes.Unauthenticated, "session no longer matches the node; register again")
	}
	// Disabling a node ends its netmap stream, but the session it earned before
	// that used to keep working for everything else: a disabled device went on
	// reporting endpoints, connections and service health for as long as it
	// stayed connected. The kill switch covers the whole session.
	if node.Disabled {
		s.sessions.forget(token)
		return nil, status.Error(codes.PermissionDenied, "node is disabled")
	}
	return node, nil
}

// GetRegisterChallenge issues the one-time challenge RegisterNode requires an
// answer to (mesh protocol v2, nodeauth.go). The auth key is resolved here too:
// an anonymous caller must not be able to make the coordinator hold state.
func (s *Server) GetRegisterChallenge(ctx context.Context, req *meshpb.GetRegisterChallengeRequest) (*meshpb.GetRegisterChallengeResponse, error) {
	if req.GetAuthKey() == "" && req.GetNodeId() != 0 {
		// Re-registration by proof alone (node_reauth). Only the local checks
		// here: the identity service is asked in RegisterNode, after the proof,
		// so a caller that merely knows a node's id and public key - every peer
		// does - cannot make the coordinator call it.
		node, err := s.reauthTarget(ctx, req.GetNodeId(), req.GetNodeKey())
		if err != nil {
			return nil, err
		}
		id, ch, err := s.sessions.issueNodeChallenge(node.Meshnet, node.ID)
		if err != nil {
			if errors.Is(err, errTooManyChallenges) {
				return nil, status.Error(codes.ResourceExhausted, err.Error())
			}
			return nil, status.Errorf(codes.Internal, "registration challenge: %v", err)
		}
		return &meshpb.GetRegisterChallengeResponse{ChallengeId: id, Challenge: ch.Encode()}, nil
	}
	ident, err := s.auth.Resolve(ctx, req.GetAuthKey())
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "auth key denied")
	}
	id, ch, err := s.sessions.issueChallenge(ident.Meshnet)
	if err != nil {
		if errors.Is(err, errTooManyChallenges) {
			return nil, status.Error(codes.ResourceExhausted, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "registration challenge: %v", err)
	}
	return &meshpb.GetRegisterChallengeResponse{ChallengeId: id, Challenge: ch.Encode()}, nil
}

// reauthTarget loads the node a re-registration by proof alone names and applies
// every check that needs nothing but the node's own record. The codes tell the
// device what to do next: NotFound and FailedPrecondition (signed out) mean
// "enroll with an auth key", PermissionDenied means disabled.
func (s *Server) reauthTarget(ctx context.Context, nodeID int64, rawKey string) (*core.Node, error) {
	key, err := meshproto.ParseNodeKey(rawKey)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "node_key: %v", err)
	}
	node, err := s.coord.Nodes.Get(ctx, nodeID)
	if err != nil {
		if errors.Is(err, core.ErrNodeNotFound) {
			return nil, status.Error(codes.NotFound, "node not found; enroll with an auth key")
		}
		return nil, status.Errorf(codes.Internal, "load node: %v", err)
	}
	if node.NodeKey != key {
		return nil, status.Error(codes.Unauthenticated, "node_key does not match the node")
	}
	if node.Disabled {
		return nil, status.Error(codes.PermissionDenied, "node is disabled")
	}
	if node.SignedOut {
		return nil, status.Error(codes.FailedPrecondition, "node signed out; enroll with an auth key")
	}
	return node, nil
}

// admittedBy reports whether the node with this key in this meshnet already
// enrolled as principal. An empty principal (a key-file entry) never counts:
// those keys have nothing to spend anyway.
func (s *Server) admittedBy(ctx context.Context, meshnet core.MeshnetID, key meshproto.NodeKey, principal string) bool {
	if principal == "" {
		return false
	}
	n, err := s.coord.Nodes.FindByKey(ctx, meshnet, key)
	return err == nil && n != nil && n.EnrolledBy == principal
}

// SignOut marks the caller's node signed out (core.Node.SignedOut) and ends its
// session. The node keeps its record and address; it comes back only by
// enrolling with an auth key.
func (s *Server) SignOut(ctx context.Context, req *meshpb.SignOutRequest) (*meshpb.SignOutResponse, error) {
	node, err := s.authorizeNode(ctx, req.GetSessionToken(), 0)
	if err != nil {
		return nil, err
	}
	if err := s.coord.SignOut(ctx, node.ID); err != nil {
		if errors.Is(err, core.ErrNodeNotFound) {
			return nil, status.Error(codes.NotFound, "node not found")
		}
		return nil, status.Errorf(codes.Internal, "sign out: %v", err)
	}
	s.sessions.forget(req.GetSessionToken())
	return &meshpb.SignOutResponse{}, nil
}

// ListNodes lists the caller's meshnet for a self-hosted coordinator's apps
// (see the proto). Every device in the meshnet, not only the ones the caller's
// ACL lets it reach: a person looking at their own network wants to see the
// machine that is offline or that the rules keep from this phone.
func (s *Server) ListNodes(ctx context.Context, req *meshpb.ListNodesRequest) (*meshpb.ListNodesResponse, error) {
	if !s.coord.SelfHosted() {
		return nil, status.Error(codes.PermissionDenied, "device lists come from the platform API on this coordinator")
	}
	self, err := s.authorizeReader(ctx, req.GetSessionToken())
	if err != nil {
		return nil, err
	}
	nodes, err := s.coord.MeshnetNodes(ctx, self.Meshnet)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list: %v", err)
	}
	out := &meshpb.ListNodesResponse{}
	for _, n := range nodes {
		info := &meshpb.NodeInfo{
			Id: n.ID, Name: n.Name, Os: n.OS, Online: s.coord.Presence.IsOnline(n.ID),
			Disabled: n.Disabled, Approved: n.Approved,
		}
		if n.Overlay.IsValid() {
			info.OverlayAddr = n.Overlay.String()
		}
		if !n.LastSeen.IsZero() {
			info.LastSeenUnix = n.LastSeen.Unix()
		}
		for _, r := range n.ApprovedRoutes {
			info.ApprovedRoutes = append(info.ApprovedRoutes, r.String())
		}
		for _, sv := range n.Services {
			if sv.Approved {
				info.Services = append(info.Services, &meshpb.PeerService{Name: sv.Name, Proto: sv.Proto, Port: uint32(sv.Port)})
			}
		}
		out.Nodes = append(out.Nodes, info)
	}
	return out, nil
}

// UpdateNodeDeclarations records new declarations for a node that is ALREADY
// enrolled, without touching its session.
//
// Authorized by the session RegisterNode issued (mesh protocol v2), like every
// other node-scoped call. It used to resolve "auth key + node key", which is
// exactly what let an org member edit a colleague's device (security audit 1-C,
// same-org residual). A node_key, when sent, must still name the session's node.
//
// Peers still get bumped: declarations are ACL "svc:" selectors, so the
// coordinator recompiles each receiver's port filter from them.
func (s *Server) UpdateNodeDeclarations(ctx context.Context, req *meshpb.UpdateNodeDeclarationsRequest) (*meshpb.UpdateNodeDeclarationsResponse, error) {
	self, err := s.authorizeNode(ctx, req.GetSessionToken(), 0)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			// "You aren't enrolled here": the caller's answer is to enroll.
			return nil, status.Error(codes.FailedPrecondition, "node is not enrolled in this meshnet")
		}
		return nil, err
	}
	if raw := req.GetNodeKey(); raw != "" {
		if k, perr := meshproto.ParseNodeKey(raw); perr != nil || k != self.NodeKey {
			return nil, status.Error(codes.PermissionDenied, "node_key does not match the session")
		}
	}
	in := core.UpdateDeclarationsInput{
		Meshnet:           self.Meshnet,
		NodeKey:           self.NodeKey,
		DeviceFingerprint: req.GetDeviceFingerprint(),
		OS:                req.GetOs(),
		BlockIncoming:     req.BlockIncoming,
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
			return nil, status.Error(codes.FailedPrecondition, "node is not enrolled in this meshnet")
		case errors.Is(err, core.ErrNodeDisabled):
			return nil, status.Error(codes.PermissionDenied, err.Error())
		default:
			return nil, status.Errorf(codes.Internal, "update declarations: %v", err)
		}
	}
	s.notif.Bump(self.Meshnet)
	return &meshpb.UpdateNodeDeclarationsResponse{NodeId: node.ID}, nil
}

// RegisterNode authenticates the node's auth key to a meshnet, allocates its
// overlay address, persists it, and notifies existing peers so they pick it up.
func (s *Server) RegisterNode(ctx context.Context, req *meshpb.RegisterNodeRequest) (*meshpb.RegisterNodeResponse, error) {
	// Mesh protocol v2 proves the device at registration and authorizes every
	// later call by the session that earns (nodeauth.go). An older client can do
	// neither; letting it half-enroll would only make it retry forever, every
	// retry bumping each peer in its meshnet. Refusing it here is the same outcome
	// without that churn, and with an error that says why.
	if v := req.GetProtocolVersion(); v < minNodeProtocolVersion {
		return nil, status.Errorf(codes.FailedPrecondition,
			"mesh protocol v%d is no longer accepted; this coordinator requires v%d or newer - upgrade calabi", v, minNodeProtocolVersion)
	}
	nodeKey, err := meshproto.ParseNodeKey(req.GetNodeKey())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "node_key: %v", err)
	}
	// Who the node is, and which meshnet: from the auth key, or - re-registering
	// by proof alone (node_reauth) - from the node's own record, since without a
	// key there is nothing else to take it from.
	var (
		ident         core.Identity
		reauth        = req.GetAuthKey() == "" && req.GetNodeId() != 0
		challengeNode int64
	)
	if reauth {
		node, err := s.reauthTarget(ctx, req.GetNodeId(), req.GetNodeKey())
		if err != nil {
			return nil, err
		}
		ident = core.Identity{Meshnet: node.Meshnet, Tags: node.Tags, UserID: node.OwnerUserID, Principal: node.EnrolledBy}
		challengeNode = node.ID
	} else {
		ident, err = s.auth.Resolve(ctx, req.GetAuthKey())
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "auth key denied")
		}
	}
	meshnet := ident.Meshnet
	// Proof of possession (mesh protocol v2). The auth key above says which org
	// the caller belongs to; only this says which DEVICE it is. Without it a
	// member could re-enroll a colleague's node - node keys are public within an
	// org - and be handed that device's record (security audit 1-C).
	pending, ok := s.sessions.takeChallenge(req.GetChallengeId(), meshnet, challengeNode)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "registration challenge missing, expired or already used; call GetRegisterChallenge first")
	}
	if err := meshproto.OpenRegisterProof(pending.ch, pending.ephPriv, nodeKey, req.GetRegisterProof()); err != nil {
		return nil, status.Error(codes.Unauthenticated, "registration proof rejected: the caller does not hold this node key")
	}
	if reauth {
		// What a credential got checked for on every reconnect until now: a
		// revoked API key, a removed member, a suspended account. Asked only
		// here, after the proof, so a caller that is not the device costs the
		// identity service nothing.
		if err := s.auth.Reauthorize(ctx, meshnet, ident.Principal); err != nil {
			if errors.Is(err, core.ErrAuthDenied) {
				return nil, status.Error(codes.Unauthenticated, "what this device enrolled with no longer admits it; enroll with an auth key")
			}
			return nil, status.Error(codes.Unavailable, "cannot confirm this device's enrollment right now")
		}
	}
	// A key with a limited number of uses, or an expiry, spends one per device
	// it admits (core/authkeys.go). The device it already admitted is not a new
	// one: presenting the key again - a desktop with the key in its config file
	// does after every restart - costs nothing and is not refused for an expiry
	// or a use limit that only ever applied to newcomers.
	undoSpend := func() {}
	if !reauth && !s.admittedBy(ctx, meshnet, nodeKey, ident.Principal) {
		undo, err := s.auth.Spend(ctx, ident.Principal)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "auth key expired, used up or revoked")
		}
		undoSpend = undo
	}
	in := core.RegisterInput{
		Meshnet:           meshnet,
		Name:              req.GetName(),
		NodeKey:           nodeKey,
		Tags:              ident.Tags,
		OwnerUserID:       ident.UserID,
		EnrolledBy:        ident.Principal,
		Reauth:            reauth,
		DeviceFingerprint: req.GetDeviceFingerprint(),
		OS:                req.GetOs(),
		BlockIncoming:     req.BlockIncoming,
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
	// Which of those the node wants published under a stand-in prefix. Not
	// validated against advertised_routes here: core reconciles against the
	// APPROVED set anyway, so a stray entry is inert rather than an error, and
	// rejecting the whole registration over one would take the node off the mesh
	// for a request it could simply not be granted.
	for _, raw := range req.GetAliasedRoutes() {
		pfx, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "aliased_route %q: %v", raw, err)
		}
		in.AliasedRoutes = append(in.AliasedRoutes, pfx.Masked())
	}

	node, err := s.coord.Register(ctx, in)
	if err != nil {
		undoSpend()
		switch {
		case errors.Is(err, core.ErrNodeQuotaExceeded):
			return nil, status.Error(codes.ResourceExhausted, err.Error())
		case errors.Is(err, core.ErrNodeDisabled):
			return nil, status.Error(codes.PermissionDenied, err.Error())
		case errors.Is(err, core.ErrNodeSignedOut):
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		case errors.Is(err, core.ErrNodeNotFound):
			return nil, status.Error(codes.NotFound, "node not found; enroll with an auth key")
		default:
			return nil, status.Errorf(codes.Internal, "register: %v", err)
		}
	}

	// The session every node-scoped call will be authorized by (nodeauth.go).
	token, err := s.sessions.start(node)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "start session: %v", err)
	}
	// Peers in this meshnet should learn about the newcomer.
	s.notif.Bump(meshnet)

	ver, caps := negotiate(req.GetProtocolVersion(), req.GetCapabilities())
	return &meshpb.RegisterNodeResponse{
		NodeId:          node.ID,
		OverlayAddr:     node.Overlay.String(),
		ProtocolVersion: ver,
		Capabilities:    caps,
		SessionToken:    token,
	}, nil
}

// PullNetMap streams the node's netmap: an initial snapshot, then a fresh one
// every time its meshnet changes, until the client disconnects.
//
// The stream is bound to the caller: authorizeNode checks that the session token
// names this node before a byte of netmap is sent. It used to be keyed by
// node_id alone (a MESH.1 simplification that outlived its note), which let
// anyone read any org netmap - security audit 1-C.
func (s *Server) PullNetMap(req *meshpb.PullNetMapRequest, stream meshpb.Coordinator_PullNetMapServer) error {
	ctx := stream.Context()
	self, err := s.authorizeNode(ctx, req.GetSessionToken(), req.GetNodeId())
	if err != nil {
		return err
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
	self, err := s.authorizeNode(ctx, req.GetSessionToken(), req.GetNodeId())
	if err != nil {
		return nil, err
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

// ReportConnections stores who this node exchanged traffic with, by the hour.
//
// Authorized by the session, like every other post-registration call, and the
// node it reports FOR is the session's own node — never the node_key in the
// request. A node may only ever add rows about itself; without that, one member
// could write an access trail implicating a colleague's machine, which is a
// worse failure than having no trail at all.
//
// A coordinator that keeps no trail (ConnRecords nil) accepts the call and
// stores nothing, so the same daemon works against both.
func (s *Server) ReportConnections(ctx context.Context, req *meshpb.ReportConnectionsRequest) (*meshpb.ReportConnectionsResponse, error) {
	self, err := s.authorizeNode(ctx, req.GetSessionToken(), 0)
	if err != nil {
		return nil, err
	}
	samples := make([]core.ConnSample, 0, len(req.GetSamples()))
	for _, x := range req.GetSamples() {
		key, kerr := meshproto.ParseNodeKey(x.GetPeerNodeKey())
		if kerr != nil {
			// An unparseable key is dropped, not an error: one bad entry must not
			// cost the rest of the report, and there is nothing to retry.
			continue
		}
		samples = append(samples, core.ConnSample{
			PeerNodeKey: key,
			WindowStart: time.Unix(x.GetWindowStart(), 0).UTC(),
			WindowEnd:   time.Unix(x.GetWindowEnd(), 0).UTC(),
			BytesTx:     x.GetBytesTx(),
			BytesRx:     x.GetBytesRx(),
			Path:        x.GetPath(),
		})
	}
	stored, err := s.coord.RecordConnections(ctx, self.ID, samples)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "record connections: %v", err)
	}
	return &meshpb.ReportConnectionsResponse{Stored: int32(stored)}, nil
}

// ReportEndpoints records a node's discovered candidate endpoints and notifies
// its peers so they can attempt direct paths (used from MESH.4).
//
// Peers are notified only when something they would see actually moved: the
// endpoint set or the measured home region. Every node re-reports each minute
// whether or not it roamed, and each notification re-sends the FULL netmap to
// every stream in the meshnet, so bumping unconditionally made an N-node meshnet
// push N netmaps a minute to every one of its nodes — a radio wake-up each on a
// phone. The store write still happens
// on every report: it is what refreshes the node's last_seen.
func (s *Server) ReportEndpoints(ctx context.Context, req *meshpb.ReportEndpointsRequest) (*meshpb.ReportEndpointsResponse, error) {
	self, err := s.authorizeNode(ctx, req.GetSessionToken(), req.GetNodeId())
	if err != nil {
		return nil, err
	}
	eps := make([]netip.AddrPort, 0, len(req.GetEndpoints()))
	for _, raw := range req.GetEndpoints() {
		ap, err := netip.ParseAddrPort(raw)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "endpoint %q: %v", raw, err)
		}
		eps = append(eps, ap)
	}
	endpointsMoved := !sameAddrPortSet(self.Endpoints, eps)
	if err := s.coord.Nodes.UpdateEndpoints(ctx, self.ID, eps); err != nil {
		return nil, status.Errorf(codes.Internal, "update endpoints: %v", err)
	}
	// The node also reports the relay region it measured as closest (MESH.4 B2b).
	// Only a region this coordinator published is accepted; a bad one is the
	// node's bug, not a reason to lose the endpoints it just reported, so the
	// endpoint update above stands either way — and so does telling the peers.
	homeMoved, err := s.coord.SetDERPHome(ctx, self.ID, req.GetHomeRegion())
	if endpointsMoved || homeMoved {
		s.notif.Bump(self.Meshnet)
	}
	if err != nil {
		if errors.Is(err, core.ErrUnknownDERPRegion) {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "update derp home: %v", err)
	}
	return &meshpb.ReportEndpointsResponse{}, nil
}

// sameAddrPortSet reports whether a and b hold the same endpoints, ignoring
// order and duplicates: a node lists the same candidates in whatever order its
// interfaces enumerate, and peers probe all of them, so a reshuffle is not news.
func sameAddrPortSet(a, b []netip.AddrPort) bool {
	in := make(map[netip.AddrPort]bool, len(a))
	for _, ap := range a {
		in[ap] = true
	}
	seen := make(map[netip.AddrPort]bool, len(b))
	for _, ap := range b {
		if !in[ap] {
			return false
		}
		seen[ap] = true
	}
	return len(seen) == len(in)
}

// negotiate returns the working protocol version + capability subset: the min of
// what the client and this coordinator support. v0 defines no capabilities.
func negotiate(clientVer uint32, clientCaps []string) (uint32, []string) {
	ver := clientVer
	if ver > meshproto.ProtocolVersion {
		ver = meshproto.ProtocolVersion
	}
	var caps []string
	for _, c := range clientCaps {
		if serverCapabilities.Supports(meshproto.Capability(c)) {
			caps = append(caps, c)
		}
	}
	return ver, caps
}

// serverCapabilities is what this coordinator does beyond the base protocol.
// RegisterNodeResponse carries the part the node also asked for.
var serverCapabilities = meshproto.Capabilities{meshproto.CapNodeReauth}
