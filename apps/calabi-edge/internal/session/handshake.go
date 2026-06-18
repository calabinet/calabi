package session

import (
	"errors"
	"fmt"
	"time"

	proto "github.com/calabi/calabi/pkg/protocol"
)

// HandshakeDeadline is the maximum wall-clock duration a server gives a
// client to complete HELLO + AUTH before forcibly closing.
const HandshakeDeadline = 10 * time.Second

// TokenVerifier resolves a bearer token to a tenant context.
// swaps the implementation for an identity-svc gRPC client.
type TokenVerifier interface {
	Verify(token string) (tenantID, workspaceID, clientID string, ok bool)
}

// HandshakeResult is what a successful PerformServerHandshake yields.
type HandshakeResult struct {
	TenantID    string
	WorkspaceID string
	ClientID    string
	// DeviceID is the identity-svc clients.id from AUTH; 0 = unknown.
	DeviceID int64
}

// PerformServerHandshake runs the server side of the HELLO + AUTH exchange.
//
// On success the Session has its identity fields populated and the caller
// should add it to the Manager. On failure an ERROR frame is sent and the
// stream is left in an undefined state -- caller must close.
//
// baseDomain is the edge's HTTPListener.BaseDomain — surfaced via AUTH_RESP
// so the daemon UI can render TCP/UDP public addrs as `<base>:<port>`
// instead of falling back to the daemon's snap.server_addr host (which in
// dev is literally "localhost"). Empty string is fine — old daemons fall
// back to the snap path.
func (s *Session) PerformServerHandshake(
	serverID, region, baseDomain string,
	httpPort, httpsPort uint32,
	verify TokenVerifier,
) (HandshakeResult, error) {
	deadline := time.Now().Add(HandshakeDeadline)

	// -- 1) read HELLO ----------------------------------------------------

	hf, err := s.ReadFrame()
	if err != nil {
		return HandshakeResult{}, fmt.Errorf("read HELLO: %w", err)
	}
	if hf.Type != proto.FrameHello {
		_ = s.sendError(proto.CodeUnexpectedFrame, "calabi.err.unexpected_frame",
			fmt.Sprintf("expected HELLO, got %s", hf.Type))
		return HandshakeResult{}, errors.New("expected HELLO")
	}
	var hello proto.HelloRequest
	if err := proto.Unmarshal(hf.Payload, &hello); err != nil {
		_ = s.sendError(proto.CodeMalformedPayload, "calabi.err.malformed_payload", err.Error())
		return HandshakeResult{}, err
	}

	if hello.ProtocolMajor != uint32(proto.CurrentMajor) {
		_ = s.sendError(proto.CodeUnsupportedVersion, "calabi.err.unsupported_version",
			fmt.Sprintf("server v%d, client v%d", proto.CurrentMajor, hello.ProtocolMajor))
		return HandshakeResult{}, errors.New("unsupported protocol version")
	}

	// -- 2) reply HELLO_ACK ----------------------------------------------

	ack := &proto.HelloAck{
		ProtocolMajor:       uint32(proto.CurrentMajor),
		ServerID:            serverID,
		Region:              region,
		SuggestedTransport:  proto.TransportTLSTCP,
		HeartbeatIntervalMs: 15_000,
		ConfigEpoch:         0,
	}
	if err := s.SendControl(proto.FrameHelloAck, ack); err != nil {
		return HandshakeResult{}, fmt.Errorf("send HELLO_ACK: %w", err)
	}

	if time.Now().After(deadline) {
		_ = s.sendError(proto.CodeHandshakeTimeout, "calabi.err.handshake_timeout", "")
		return HandshakeResult{}, errors.New("handshake timeout before AUTH")
	}

	// -- 3) read AUTH -----------------------------------------------------

	af, err := s.ReadFrame()
	if err != nil {
		return HandshakeResult{}, fmt.Errorf("read AUTH: %w", err)
	}
	if af.Type != proto.FrameAuth {
		_ = s.sendError(proto.CodeUnexpectedFrame, "calabi.err.unexpected_frame",
			fmt.Sprintf("expected AUTH, got %s", af.Type))
		return HandshakeResult{}, errors.New("expected AUTH")
	}
	var auth proto.AuthRequest
	if err := proto.Unmarshal(af.Payload, &auth); err != nil {
		_ = s.sendError(proto.CodeMalformedPayload, "calabi.err.malformed_payload", err.Error())
		return HandshakeResult{}, err
	}

	tenantID, wsID, clientID, ok := verify.Verify(auth.Token)
	if !ok {
		resp := &proto.AuthResponse{
			Error: proto.NewError(proto.CodeAuthInvalidToken,
				"calabi.err.auth.invalid_token", "token not recognized"),
		}
		_ = s.SendControl(proto.FrameAuthResp, resp)
		return HandshakeResult{}, errors.New("auth invalid token")
	}

	// -- 4) reply AUTH_RESP ----------------------------------------------

	s.TenantID = tenantID
	s.WorkspaceID = wsID
	s.ClientID = clientID
	s.DeviceID = auth.DeviceID

	// AUTH_RESP.Quotas is an *informational* snapshot — clients use it
	// for UX hints (e.g., "you can open up to N tunnels") but the
	// authoritative numbers live in /v1/me on bff-console and are
	// enforced server-side by tunnel-svc + the online-cap admit hook.
	// Leaving the values at 0 here means "client should ask /v1/me";
	// we used to hard-code 10/5 which silently lied to upgraded users.
	// TODO(quota-aware-auth): plumb a QuotaResolver through Manager so
	// these numbers reflect the real plan at handshake time.
	resp := &proto.AuthResponse{
		TenantID:    tenantID,
		WorkspaceID: wsID,
		ClientID:    clientID,
		SessionID:   s.ID,
		Quotas: &proto.QuotaSnapshot{
			MaxTunnels:        0,
			MaxOnlineClients:  0,
			BandwidthBps:      0,
			AllowedProxyTypes: []string{"http", "tcp"},
		},
		// see PerformServerHandshake doc.
		BaseDomain: baseDomain,
		HTTPPort:   httpPort,
		HTTPSPort:  httpsPort,
	}
	if err := s.SendControl(proto.FrameAuthResp, resp); err != nil {
		return HandshakeResult{}, fmt.Errorf("send AUTH_RESP: %w", err)
	}

	return HandshakeResult{
		TenantID:    tenantID,
		WorkspaceID: wsID,
		ClientID:    clientID,
		DeviceID:    auth.DeviceID,
	}, nil
}

func (s *Session) sendError(code int, key, en string) error {
	return s.SendControl(proto.FrameError, proto.NewError(code, key, en))
}
