package mesh

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

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
}

// NewCoordClient wraps an existing gRPC connection.
func NewCoordClient(cc grpc.ClientConnInterface) *CoordClient {
	return &CoordClient{rpc: meshpb.NewCoordinatorClient(cc)}
}

// RegisterParams is what a node presents to enroll.
type RegisterParams struct {
	AuthKey  string // tk_ auth key (platform) / pre-shared key (self-hosted)
	NodeKey  meshproto.NodeKey
	DiscoKey meshproto.DiscoKey // optional until MESH.4
	Name     string
	// AdvertiseRoutes are subnet-router CIDRs this node offers to forward (MESH.7).
	AdvertiseRoutes []netip.Prefix
	// DeviceFingerprint is this install's Publish-side device id. Sent so the
	// console can link this mesh device to its client record; empty when the
	// install never registered a device. Display only — the coordinator does
	// not authorize on it.
	DeviceFingerprint string
	// Services are what this node's config declares it offers. A CLAIM: the
	// coordinator records them pending and an admin confirms them in the console
	// before any ACL "svc:" rule matches.
	Services []DeclaredService
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
}

// Register enrolls the node and returns its mesh identity (id + overlay addr).
func (c *CoordClient) Register(ctx context.Context, p RegisterParams) (Registration, error) {
	req := &meshpb.RegisterNodeRequest{
		AuthKey:           p.AuthKey,
		NodeKey:           p.NodeKey.String(),
		Name:              p.Name,
		ProtocolVersion:   meshproto.ProtocolVersion,
		DeviceFingerprint: p.DeviceFingerprint,
	}
	if !p.DiscoKey.IsZero() {
		req.DiscoKey = p.DiscoKey.String()
	}
	for _, r := range p.AdvertiseRoutes {
		req.AdvertisedRoutes = append(req.AdvertisedRoutes, r.String())
	}
	for _, s := range p.Services {
		req.DeclaredServices = append(req.DeclaredServices, &meshpb.DeclaredService{
			Name: s.Name, Proto: s.Proto, Port: uint32(s.Port), Target: s.Target, Note: s.Note,
		})
	}
	resp, err := c.rpc.RegisterNode(ctx, req)
	if err != nil {
		return Registration{}, err
	}
	reg := Registration{NodeID: resp.GetNodeId(), ProtocolVersion: resp.GetProtocolVersion()}
	if oa := resp.GetOverlayAddr(); oa != "" {
		addr, err := netip.ParseAddr(oa)
		if err != nil {
			return Registration{}, fmt.Errorf("mesh: bad overlay_addr %q: %w", oa, err)
		}
		reg.Overlay = addr
	}
	return reg, nil
}

// ReportEndpoints uploads the node's freshly discovered candidate endpoints so
// peers can attempt direct paths to it (MESH.4), together with the relay region
// it measured as closest (homeRegion; "" = not measured yet, keep the current
// home). Endpoints are host:port; the coordinator stores both and re-pushes
// affected netmaps.
func (c *CoordClient) ReportEndpoints(ctx context.Context, nodeID int64, eps []netip.AddrPort, homeRegion string) error {
	req := &meshpb.ReportEndpointsRequest{NodeId: nodeID, HomeRegion: homeRegion}
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
	req := &meshpb.ReportServiceHealthRequest{NodeId: nodeID}
	for _, r := range in {
		req.Services = append(req.Services, &meshpb.ServiceHealth{
			Name: r.Name, TargetOk: r.TargetOK, MeshOk: r.MeshOK, Checked: r.Checked,
		})
	}
	_, err := c.rpc.ReportServiceHealth(ctx, req)
	return err
}

func (c *CoordClient) Watch(ctx context.Context, nodeID int64, onNetMap func(NetMap)) error {
	stream, err := c.rpc.PullNetMap(ctx, &meshpb.PullNetMapRequest{NodeId: nodeID})
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
func (c *CoordClient) UpdateDeclarations(ctx context.Context, p RegisterParams) error {
	req := &meshpb.UpdateNodeDeclarationsRequest{
		AuthKey:           p.AuthKey,
		NodeKey:           p.NodeKey.String(),
		DeviceFingerprint: p.DeviceFingerprint,
	}
	for _, s := range p.Services {
		req.DeclaredServices = append(req.DeclaredServices, &meshpb.DeclaredService{
			Name: s.Name, Proto: s.Proto, Port: uint32(s.Port), Target: s.Target, Note: s.Note,
		})
	}
	if _, err := c.rpc.UpdateNodeDeclarations(ctx, req); err != nil {
		switch status.Code(err) {
		case codes.FailedPrecondition, codes.Unimplemented:
			return ErrNotEnrolled
		}
		return err
	}
	return nil
}
