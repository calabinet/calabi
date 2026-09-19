package mesh

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
	meshpb "github.com/calabi/calabi/pkg/mesh-proto/meshpb"
)

// CoordClient is the client-side wrapper over the mesh Coordinator RPC: it
// enrolls the node and watches its netmap. Transport is a plain grpc conn — in
// production the daemon dials the coordinator through the bff-console public
// entrypoint, so the client keeps exactly one public ingress.
type CoordClient struct {
	rpc meshpb.CoordinatorClient

	// The session RegisterNode returned (mesh protocol v2), sent on every
	// node-scoped call after it. The coordinator issues it only to a node that
	// proved it holds its private key, so it - not the org auth key - is what
	// says which device is calling.
	sessMu  sync.Mutex
	session string
}

// NewCoordClient wraps an existing gRPC connection.
func NewCoordClient(cc grpc.ClientConnInterface) *CoordClient {
	return &CoordClient{rpc: meshpb.NewCoordinatorClient(cc)}
}

// RegisterParams is what a node presents to enroll.
type RegisterParams struct {
	AuthKey string // tk_ auth key (platform) / pre-shared key (self-hosted)
	NodeKey meshproto.NodeKey
	// NodePrivate is the private half of NodeKey. It never leaves the node: it
	// seals the registration proof (mesh protocol v2), which is how the
	// coordinator knows the caller is this device and not merely a member of its
	// org who read NodeKey out of a netmap.
	NodePrivate PrivateKey
	DiscoKey    meshproto.DiscoKey // optional until MESH.4
	Name        string
	// AdvertiseRoutes are subnet-router CIDRs this node offers to forward (MESH.7).
	AdvertiseRoutes []netip.Prefix
	// AliasRoutes are the AdvertiseRoutes this node asks to be published under a
	// unique stand-in prefix, because it expects them to collide with consumers'
	// own LANs. Only the publisher can know that — the coordinator cannot
	// anyone's local subnets. A request: it takes route approval to be granted.
	AliasRoutes []netip.Prefix
	// DeviceFingerprint is this install's Publish-side device id. Sent so the
	// console can link this mesh device to its client record; empty when the
	// install never registered a device. Display only — the coordinator does
	// not authorize on it.
	DeviceFingerprint string
	// BlockIncoming is this machine's own shields switch, REPORTED so the console
	// can show it. It is not how the setting takes effect — enforcement is the
	// node's own packet filter, which is why it holds with the coordinator
	// unreachable and in orgs that never wrote an ACL. Stamped from
	// Controller.BlockIncoming on the way out (registerParams), so there is one
	// source of truth for it.
	BlockIncoming bool
	// Services are what this node's config declares it offers. A CLAIM: the
	// coordinator records them pending and an admin confirms them in the console
	// before any ACL "svc:" rule matches.
	Services []DeclaredService
	// NodeID and Reauth: this device already is node NodeID, and its coordinator
	// offered CapNodeReauth, so Register first comes back by proof of the node
	// key alone, without AuthKey.
	// If the coordinator refuses that, Register falls back to AuthKey — unless
	// there is none, or the node is disabled. Set from a ReauthState.
	NodeID int64
	Reauth bool
}

// DeclaredService is one entry of RegisterParams.Services.
type DeclaredService struct {
	Name  string
	Proto string // "tcp" or "udp"
	// Port is what mesh PEERS dial on this node's overlay address.
	Port int
	// Target is what THIS machine dials to reach the application, e.g.
	// "127.0.0.1:5432" or a box on its LAN. Empty means 127.0.0.1:<port>.
	// Opening Port in the packet filter does nothing if the app is bound to
	// loopback only — the two are separate for exactly that reason.
	Target string
	Note   string
}

// Registration is the coordinator's answer.
type Registration struct {
	NodeID          int64
	Overlay         netip.Addr
	ProtocolVersion uint32
	// Capabilities is what the coordinator agreed to, of what this client asked
	// for (clientCapabilities).
	Capabilities meshproto.Capabilities
	// Reauth says this registration was by proof alone, without the auth key.
	Reauth bool
}

// clientCapabilities is what this client asks the coordinator for.
var clientCapabilities = []string{string(meshproto.CapNodeReauth)}

// Register enrolls the node and returns its mesh identity (id + overlay addr).
//
// With p.Reauth and p.NodeID it first re-registers by proof of the node key
// alone. A refusal falls back to enrolling with p.AuthKey, except when there is
// no key to fall back on, or when the node is disabled (PermissionDenied: a key
// would be refused too). The error returned is then the re-registration's, so
// the caller can tell "enroll again" (NotFound, FailedPrecondition,
// Unauthenticated) from "try later" (Unavailable).
func (c *CoordClient) Register(ctx context.Context, p RegisterParams) (Registration, error) {
	if p.Reauth && p.NodeID != 0 {
		reg, err := c.register(ctx, p, true)
		if err == nil || p.AuthKey == "" || status.Code(err) == codes.PermissionDenied {
			return reg, err
		}
	}
	return c.register(ctx, p, false)
}

// register is one registration: with the auth key, or (reauth) by proof alone.
func (c *CoordClient) register(ctx context.Context, p RegisterParams, reauth bool) (Registration, error) {
	// Without the private key there is nothing to prove possession with, and a
	// mismatched one would only be refused by the coordinator a round trip later
	// with a less useful error.
	if p.NodePrivate == (PrivateKey{}) || p.NodePrivate.Public() != p.NodeKey {
		return Registration{}, errors.New("mesh: register: NodePrivate is missing or does not match NodeKey")
	}
	req := &meshpb.RegisterNodeRequest{
		AuthKey:           p.AuthKey,
		NodeKey:           p.NodeKey.String(),
		Name:              p.Name,
		ProtocolVersion:   meshproto.ProtocolVersion,
		Capabilities:      clientCapabilities,
		DeviceFingerprint: p.DeviceFingerprint,
		// runtime.GOOS, not a config field: this has to be the truth about the
		// running binary, and a value an operator could set would only ever be
		// wrong. It is display-only on the far side, so nothing rests on it.
		Os: runtime.GOOS,
		// Always sent (a pointer to a real bool, never nil), so "off" is a
		// statement rather than silence. Only a daemon too old to know the field
		// leaves it absent, which is the state the console renders as nothing.
		BlockIncoming: &p.BlockIncoming,
	}
	if !p.DiscoKey.IsZero() {
		req.DiscoKey = p.DiscoKey.String()
	}
	for _, r := range p.AdvertiseRoutes {
		req.AdvertisedRoutes = append(req.AdvertisedRoutes, r.String())
	}
	for _, r := range p.AliasRoutes {
		req.AliasedRoutes = append(req.AliasedRoutes, r.String())
	}
	for _, s := range p.Services {
		req.DeclaredServices = append(req.DeclaredServices, &meshpb.DeclaredService{
			Name: s.Name, Proto: s.Proto, Port: uint32(s.Port), Target: s.Target, Note: s.Note,
		})
	}
	if reauth {
		req.AuthKey, req.NodeId = "", p.NodeID
	}
	if err := c.attachProof(ctx, req, p, reauth); err != nil {
		return Registration{}, err
	}
	resp, err := c.rpc.RegisterNode(ctx, req)
	if err != nil {
		return Registration{}, err
	}
	c.sessMu.Lock()
	c.session = resp.GetSessionToken()
	c.sessMu.Unlock()
	reg := Registration{NodeID: resp.GetNodeId(), ProtocolVersion: resp.GetProtocolVersion(), Reauth: reauth}
	for _, cap := range resp.GetCapabilities() {
		reg.Capabilities = append(reg.Capabilities, meshproto.Capability(cap))
	}
	if oa := resp.GetOverlayAddr(); oa != "" {
		addr, err := netip.ParseAddr(oa)
		if err != nil {
			return Registration{}, fmt.Errorf("mesh: bad overlay_addr %q: %w", oa, err)
		}
		reg.Overlay = addr
	}
	return reg, nil
}

// SignOut tells the coordinator this device signed out: it will not take the
// node back by proof alone until the device enrolls with an auth key again. The
// session ends with it.
func (c *CoordClient) SignOut(ctx context.Context) error {
	tok := c.sessionToken()
	if tok == "" {
		return errors.New("mesh: sign out: not registered")
	}
	_, err := c.rpc.SignOut(ctx, &meshpb.SignOutRequest{SessionToken: tok})
	return err
}

// sessionToken is the session the node registered into ("" before Register).
func (c *CoordClient) sessionToken() string {
	c.sessMu.Lock()
	defer c.sessMu.Unlock()
	return c.session
}

// attachProof answers the coordinator's registration challenge with the node's
// private key (mesh protocol v2).
//
// A coordinator that predates v2 answers Unimplemented: it issues no challenge
// and asks for no proof, so the registration goes ahead without one. That is
// what lets this client ship before the coordinator does. It is not a downgrade
// an attacker can force - in production the coordinator is reached over TLS
// verified against the embedded CA, so only the real coordinator can answer, and
// a real coordinator new enough to check refuses an unproven registration.
//
// A re-registration by proof alone (reauth) asks for a challenge bound to the
// node instead of presenting the key, and has no such fallback: a coordinator
// without challenges never offered node_reauth.
func (c *CoordClient) attachProof(ctx context.Context, req *meshpb.RegisterNodeRequest, p RegisterParams, reauth bool) error {
	chReq := &meshpb.GetRegisterChallengeRequest{AuthKey: p.AuthKey}
	if reauth {
		chReq = &meshpb.GetRegisterChallengeRequest{NodeId: p.NodeID, NodeKey: p.NodeKey.String()}
	}
	chr, err := c.rpc.GetRegisterChallenge(ctx, chReq)
	if status.Code(err) == codes.Unimplemented && !reauth {
		return nil
	}
	if err != nil {
		return err
	}
	ch, err := meshproto.ParseRegisterChallenge(chr.GetChallenge())
	if err != nil {
		return fmt.Errorf("mesh: registration challenge: %w", err)
	}
	req.ChallengeId = chr.GetChallengeId()
	req.RegisterProof = meshproto.SealRegisterProof(ch, p.NodeKey, [meshproto.KeyLen]byte(p.NodePrivate))
	return nil
}

// ReportEndpoints uploads the node's freshly discovered candidate endpoints so
// peers can attempt direct paths to it (MESH.4), together with the relay region
// it measured as closest (homeRegion; "" = not measured yet, keep the current
// home). Endpoints are host:port; the coordinator stores both and re-pushes
// affected netmaps.
func (c *CoordClient) ReportEndpoints(ctx context.Context, nodeID int64, eps []netip.AddrPort, homeRegion string) error {
	req := &meshpb.ReportEndpointsRequest{NodeId: nodeID, HomeRegion: homeRegion, SessionToken: c.sessionToken()}
	for _, ep := range eps {
		req.Endpoints = append(req.Endpoints, ep.String())
	}
	_, err := c.rpc.ReportEndpoints(ctx, req)
	return err
}

// Watch opens the netmap stream and invokes onNetMap for every update the
// coordinator pushes, until ctx is cancelled or the stream ends. It returns the
// terminating error (io.EOF / context error / transport error) so the caller can
// decide whether to reconnect. A malformed netmap frame is skipped, not fatal.
// ReportServiceHealth uploads what this node observes about its own services.
// Best-effort by contract: it grants nothing, so a coordinator that rejects it
// costs a badge in the console and nothing else.
func (c *CoordClient) ReportServiceHealth(ctx context.Context, nodeID int64, in []ServiceHealthReport) error {
	if len(in) == 0 {
		return nil
	}
	req := &meshpb.ReportServiceHealthRequest{NodeId: nodeID, SessionToken: c.sessionToken()}
	for _, r := range in {
		req.Services = append(req.Services, &meshpb.ServiceHealth{
			Name: r.Name, TargetOk: r.TargetOK, MeshOk: r.MeshOK, Checked: r.Checked,
		})
	}
	_, err := c.rpc.ReportServiceHealth(ctx, req)
	return err
}

func (c *CoordClient) Watch(ctx context.Context, nodeID int64, onNetMap func(NetMap)) error {
	stream, err := c.rpc.PullNetMap(ctx, &meshpb.PullNetMapRequest{NodeId: nodeID, SessionToken: c.sessionToken()})
	if err != nil {
		return err
	}
	for {
		pb, err := stream.Recv()
		if err != nil {
			return err
		}
		nm, err := FromNetMap(pb)
		if err != nil {
			continue // skip a malformed map, keep watching
		}
		onNetMap(nm)
	}
}

// ErrNotEnrolled is what UpdateDeclarations returns when the coordinator says
// this node key isn't in the meshnet. Callers fall back to a full Register:
// there is nothing to update.
var ErrNotEnrolled = errors.New("mesh: node is not enrolled in this meshnet")

// UpdateDeclarations pushes a new service list (and device fingerprint) for an
// already-enrolled node WITHOUT re-registering it.
//
// The alternative — the only option before this existed — was to tear the
// session down and enroll again, which reconfigures WireGuard, re-dials every
// relay and re-punches every direct path. None of that is needed to change what
// the node says it offers.
//
// An older coordinator answers Unimplemented; that is reported as ErrNotEnrolled
// so the caller takes the same re-enroll fallback and the feature degrades to
// exactly the old behaviour instead of failing the edit.
//
// Unauthenticated means the session is gone - the coordinator restarted, or a
// newer registration replaced it - and re-enrolling is the fix for that too.
// ReportConnections uploads this node's per-window connection deltas.
//
// Only the peer, the window, the byte counts and direct-vs-relay travel: no
// endpoint, no public IP, no port. That is the line that lets this exist as
// history at all,
// and it is enforced here rather than only at the far end because this is the
// side that HAS the endpoint and could leak it by accident.
func (c *CoordClient) ReportConnections(ctx context.Context, p RegisterParams, samples []ConnSample) error {
	req := &meshpb.ReportConnectionsRequest{
		SessionToken: c.sessionToken(),
		NodeKey:      p.NodeKey.String(),
	}
	for _, s := range samples {
		req.Samples = append(req.Samples, &meshpb.ConnSample{
			PeerNodeKey: s.PeerNodeKey,
			WindowStart: s.WindowStart.Unix(),
			WindowEnd:   s.WindowEnd.Unix(),
			BytesTx:     s.BytesTx,
			BytesRx:     s.BytesRx,
			Path:        s.Path,
		})
	}
	_, err := c.rpc.ReportConnections(ctx, req)
	return err
}

func (c *CoordClient) UpdateDeclarations(ctx context.Context, p RegisterParams) error {
	req := &meshpb.UpdateNodeDeclarationsRequest{
		AuthKey:           p.AuthKey,
		NodeKey:           p.NodeKey.String(),
		DeviceFingerprint: p.DeviceFingerprint,
		SessionToken:      c.sessionToken(),
		// Also on this path, so a daemon upgraded in place fills the column
		// without waiting for a re-enrollment.
		Os:            runtime.GOOS,
		BlockIncoming: &p.BlockIncoming,
	}
	for _, s := range p.Services {
		req.DeclaredServices = append(req.DeclaredServices, &meshpb.DeclaredService{
			Name: s.Name, Proto: s.Proto, Port: uint32(s.Port), Target: s.Target, Note: s.Note,
		})
	}
	if _, err := c.rpc.UpdateNodeDeclarations(ctx, req); err != nil {
		switch status.Code(err) {
		case codes.FailedPrecondition, codes.Unimplemented, codes.Unauthenticated:
			return ErrNotEnrolled
		}
		return err
	}
	return nil
}

// NodeInfo is one device of the meshnet as ListNodes reports it.
type NodeInfo struct {
	ID             int64
	Name           string
	OS             string
	Overlay        string
	Online         bool
	Disabled       bool
	Approved       bool
	Services       []PeerService
	ApprovedRoutes []string
	LastSeen       time.Time
}

// ListNodes lists this node's meshnet, every device in it, from a self-hosted
// coordinator. A coordinator backed by an identity service refuses it
// (PermissionDenied): there the platform's API serves device lists.
func (c *CoordClient) ListNodes(ctx context.Context) ([]NodeInfo, error) {
	resp, err := c.rpc.ListNodes(ctx, &meshpb.ListNodesRequest{SessionToken: c.sessionToken()})
	if err != nil {
		return nil, err
	}
	out := make([]NodeInfo, 0, len(resp.GetNodes()))
	for _, n := range resp.GetNodes() {
		info := NodeInfo{
			ID: n.GetId(), Name: n.GetName(), OS: n.GetOs(), Overlay: n.GetOverlayAddr(),
			Online: n.GetOnline(), Disabled: n.GetDisabled(), Approved: n.GetApproved(),
			ApprovedRoutes: n.GetApprovedRoutes(),
		}
		if s := n.GetLastSeenUnix(); s > 0 {
			info.LastSeen = time.Unix(s, 0)
		}
		for _, sv := range n.GetServices() {
			info.Services = append(info.Services, PeerService{Name: sv.GetName(), Proto: sv.GetProto(), Port: int(sv.GetPort())})
		}
		out = append(out, info)
	}
	return out, nil
}

// EdgeTarget is one edge a self-hosted coordinator names for tunnels.
type EdgeTarget struct {
	// Addr is host:port of the edge's control listener.
	Addr string
	// Pin is meshproto.CertPin of the edge's certificate. Empty: check it
	// against the system's roots and the host name.
	Pin string
}

// EdgeAccess is where this node serves tunnels and the grant it signs in to
// the edge with.
type EdgeAccess struct {
	Edges []EdgeTarget
	// Grant is the coordinator's signed grant; empty when it signs none.
	Grant  []byte
	Expiry time.Time
}

// GetEdgeAccess asks a self-hosted coordinator where this node serves tunnels,
// and for a grant its edge accepts. Works on a view session too, so a device
// whose mesh is off still serves tunnels.
func (c *CoordClient) GetEdgeAccess(ctx context.Context) (EdgeAccess, error) {
	resp, err := c.rpc.GetEdgeAccess(ctx, &meshpb.GetEdgeAccessRequest{SessionToken: c.sessionToken()})
	if err != nil {
		return EdgeAccess{}, err
	}
	out := EdgeAccess{Grant: resp.GetGrant()}
	if s := resp.GetGrantExpiresUnix(); s > 0 {
		out.Expiry = time.Unix(s, 0)
	}
	for _, e := range resp.GetEdges() {
		out.Edges = append(out.Edges, EdgeTarget{Addr: e.GetAddr(), Pin: e.GetPin()})
	}
	return out, nil
}
