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

func (s *Server) addFileTransfers(out *meshpb.NetMap) {
	out.FileTransferSupported = true
	peers := append([]*meshpb.Peer{out.Self}, out.Peers...)
	now := time.Now()
	for _, peer := range peers {
		if peer == nil || !s.coord.Presence.IsOnline(peer.NodeId) {
			continue
		}
		s.sessions.mu.Lock()
		sess := s.sessions.byToken[s.sessions.byNode[peer.NodeId]]
		var info *meshpb.FileTransferInfo
		if sess.fileTransfer != nil {
			info = proto.Clone(sess.fileTransfer).(*meshpb.FileTransferInfo)
		}
		s.sessions.mu.Unlock()
		key, err := meshproto.ParseNodeKey(peer.NodeKey)
		if err != nil || key != sess.nodeKey {
			continue
		}
		if _, err := meshproto.VerifyFileTransfer(key, info, now); err == nil {
			peer.FileTransfer = info
		}
	}
}

func (s *Server) hasFileTransfer(nodeID int64) bool {
	s.sessions.mu.Lock()
	defer s.sessions.mu.Unlock()
	return s.sessions.byToken[s.sessions.byNode[nodeID]].fileTransfer != nil
}
