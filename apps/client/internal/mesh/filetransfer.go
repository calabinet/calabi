package mesh

import (
	"context"
	"errors"
	"net/netip"
	"time"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	"github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"google.golang.org/protobuf/proto"
)

// FileMembers includes offline peers so absence of a transfer lease can pause
// requests without being confused with authoritative membership revocation.
func (c *Controller) FileMembers() []Peer {
	c.peersMu.Lock()
	defer c.peersMu.Unlock()
	out := make([]Peer, 0, len(c.curPeers))
	for _, p := range c.curPeers {
		out = append(out, Peer{NodeKey: p.NodeKey, Overlay: p.Overlay})
	}
	return out
}

func cloneFileTransfer(info *meshpb.FileTransferInfo) *meshpb.FileTransferInfo {
	if info == nil {
		return nil
	}
	return proto.Clone(info).(*meshpb.FileTransferInfo)
}

// FileTransferReady requires both registration negotiation and a current map.
func (c *Controller) FileTransferReady() bool {
	return c.registered.Load() && c.fileTransferNegotiated.Load() && c.fileTransferMap.Load()
}

func (c *Controller) FileRelayLimit() uint32 { return c.fileRelayLimit.Load() }
func (c *Controller) FileNodeID() int64      { return c.fileNodeID.Load() }

func (c *Controller) FilePeers() []Peer {
	if !c.FileTransferReady() {
		return nil
	}
	c.peersMu.Lock()
	defer c.peersMu.Unlock()
	out := []Peer{}
	for _, p := range c.curPeers {
		if _, err := meshproto.VerifyFileTransfer(p.NodeKey, p.FileTransfer, time.Now()); err == nil {
			p.FileTransfer = cloneFileTransfer(p.FileTransfer)
			out = append(out, p)
		}
	}
	return out
}

// FilePeer resolves only exact device overlay addresses, never subnet routes.
// Revalidation on every use ensures a cached netmap cannot prolong a lease.
func (c *Controller) FilePeer(ip netip.Addr) (Peer, string, bool) {
	if !c.FileTransferReady() {
		return Peer{}, "", false
	}
	c.peersMu.Lock()
	defer c.peersMu.Unlock()
	for _, p := range c.curPeers {
		if p.Overlay != ip {
			continue
		}
		pin, err := meshproto.VerifyFileTransfer(p.NodeKey, p.FileTransfer, time.Now())
		if err != nil {
			return Peer{}, "", false
		}
		p.FileTransfer = cloneFileTransfer(p.FileTransfer)
		return p, pin, true
	}
	return Peer{}, "", false
}

// PublishFileTransfer changes metadata only; the user agent owns all files and
// private TLS keys. Withdrawing is allowed even before a new map arrives.
func (c *Controller) PublishFileTransfer(ctx context.Context, info *meshpb.FileTransferInfo) error {
	if !c.registered.Load() || !c.fileTransferNegotiated.Load() {
		return errors.New("coordinator does not support file transfer")
	}
	if info != nil {
		if _, err := meshproto.VerifyFileTransfer(c.Params.NodeKey, info, time.Now()); err != nil {
			return err
		}
	}
	_, err := c.Coord.rpc.UpdateFileTransfer(ctx, &meshpb.UpdateFileTransferRequest{SessionToken: c.Coord.sessionToken(), Info: cloneFileTransfer(info)})
	return err
}
