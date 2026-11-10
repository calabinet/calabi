package rpc

import (
	"context"
	"time"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	"github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func (s *Server) UpdateFileTransfer(ctx context.Context, req *meshpb.UpdateFileTransferRequest) (*meshpb.UpdateFileTransferResponse, error) {
	self, err := s.authorizeNode(ctx, req.GetSessionToken(), 0)
	if err != nil {
		return nil, err
	}
	if !self.Approved || self.SignedOut {
		return nil, status.Error(codes.PermissionDenied, "node is not approved or has signed out")
	}
	info := req.GetInfo()
	if info != nil {
		if _, err := meshproto.VerifyFileTransfer(self.NodeKey, info, time.Now()); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		info = proto.Clone(info).(*meshpb.FileTransferInfo)
	}
	// Same lock as session replacement: a request that raced re-registration
	// cannot advertise its old user agent in the new session.
	s.sessions.mu.Lock()
	sess, ok := s.sessions.byToken[req.GetSessionToken()]
	if ok {
		sess.fileTransfer = info
		s.sessions.byToken[req.GetSessionToken()] = sess
	}
	s.sessions.mu.Unlock()
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "session ended")
	}
	s.notif.Bump(self.Meshnet)
	return &meshpb.UpdateFileTransferResponse{}, nil
}

func (s *Server) ReportRdpCertificate(ctx context.Context, req *meshpb.ReportRdpCertificateRequest) (*meshpb.ReportRdpCertificateResponse, error) {
	node, err := s.authorizeNode(ctx, req.GetSessionToken(), 0)
	if err != nil {
		return nil, err
	}
	if node.OS != "windows" || !node.Approved || node.SignedOut || node.OwnerUserID <= 0 {
		return nil, status.Error(codes.PermissionDenied, "owned Windows device required")
	}
	pin := string(req.GetSha256())
	if len(pin) != 0 && len(pin) != 32 {
		return nil, status.Error(codes.InvalidArgument, "expected SHA-256")
	}
	s.sessions.mu.Lock()
	session, ok := s.sessions.byToken[req.GetSessionToken()]
	changed := ok && session.rdpPin != pin
	if changed {
		session.rdpPin = pin
		s.sessions.byToken[req.GetSessionToken()] = session
	}
	s.sessions.mu.Unlock()
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "session ended")
	}
	if changed {
		s.notif.Bump(node.Meshnet)
	}
	return &meshpb.ReportRdpCertificateResponse{}, nil
}

func (s *Server) addFileTransfers(out *meshpb.NetMap) {
	out.FileTransferSupported = true
	now := time.Now()
	add := func(peer *meshpb.Peer) *meshpb.Peer {
		if peer == nil || !s.coord.Presence.IsOnline(peer.NodeId) {
			return peer
		}
		s.sessions.mu.Lock()
		sess := s.sessions.byToken[s.sessions.byNode[peer.NodeId]]
		var info *meshpb.FileTransferInfo
		if sess.fileTransfer != nil {
			info = proto.Clone(sess.fileTransfer).(*meshpb.FileTransferInfo)
		}
		s.sessions.mu.Unlock()
		if info == nil && sess.rdpPin == "" {
			return peer
		}
		key, err := meshproto.ParseNodeKey(peer.NodeKey)
		if err != nil || key != sess.nodeKey {
			return peer
		}
		if peer.SameOwner && peer.Os == "windows" && sess.rdpPin != "" {
			peer = proto.Clone(peer).(*meshpb.Peer)
			peer.RdpCertificateSha256 = []byte(sess.rdpPin)
		}
		if _, err := meshproto.VerifyFileTransfer(key, info, now); err == nil {
			// Frozen public peer messages are shared; attach live state only to a
			// private copy. Expiry, online status and session identity stay live.
			peer = proto.Clone(peer).(*meshpb.Peer)
			peer.FileTransfer = info
		}
		return peer
	}
	out.Self = add(out.Self)
	for i, p := range out.Peers {
		out.Peers[i] = add(p)
	}
}

func (s *Server) hasFileTransfer(nodeID int64) bool {
	s.sessions.mu.Lock()
	defer s.sessions.mu.Unlock()
	session := s.sessions.byToken[s.sessions.byNode[nodeID]]
	return session.fileTransfer != nil || session.rdpPin != ""
}
