package protocol

import (
	"encoding/json"
	"fmt"
)

// Payload types for the Calabi wire protocol.
//
// NOTE: these structures are encoded as JSON inside frame Payload bytes
// to keep the build free of protoc. The on-the-wire MEANING is identical
// to the protobuf messages defined in proto/calabi/v1/control.proto -- the
// field names match. swaps the marshal/unmarshal calls below for the
// generated protobuf bindings without changing call sites.
//
// Versioning: JSON tags use snake_case to match protobuf field names. Add
// `omitempty` to OPTIONAL fields so they round-trip as zero values.

// ---- shared enums ------------------------------------------------------

// ProxyKind mirrors common.proto ProxyType. Kept as a string for friendly
// JSON; switches to enum int after protobuf migration.
type ProxyKind string

const (
	ProxyKindUnspecified ProxyKind = ""
	ProxyKindHTTP        ProxyKind = "http"
	ProxyKindHTTPS       ProxyKind = "https"
	ProxyKindTCP         ProxyKind = "tcp"
	ProxyKindUDP         ProxyKind = "udp"
	ProxyKindSNI         ProxyKind = "sni"
)

// TransportKind mirrors common.proto Transport.
type TransportKind string

const (
	TransportQUIC   TransportKind = "quic"
	TransportTLSTCP TransportKind = "tls-tcp"
)

// ---- error envelope ----------------------------------------------------

// ErrorPayload mirrors errors.proto Error.
type ErrorPayload struct {
	Code         int               `json:"code"`
	MessageKey   string            `json:"message_key,omitempty"`
	MessageEN    string            `json:"message_en,omitempty"`
	Details      map[string]string `json:"details,omitempty"`
	RetryAfterMs uint32            `json:"retry_after_ms,omitempty"`
}

// Error makes ErrorPayload implement the error interface.
func (e *ErrorPayload) Error() string {
	if e == nil {
		return ""
	}
	if e.MessageEN != "" {
		return fmt.Sprintf("calabi: code=%d %s", e.Code, e.MessageEN)
	}
	return fmt.Sprintf("calabi: code=%d %s", e.Code, e.MessageKey)
}

// Canonical Code values; full table in errors.proto.
const (
	CodeOK                 = 0
	CodeBadMagic           = 1001
	CodeUnsupportedVersion = 1002
	CodeFrameTooLarge      = 1003
	CodeMalformedPayload   = 1004
	CodeUnexpectedFrame    = 1005
	CodeHandshakeTimeout   = 1006
	CodeAuthRequired       = 2001
	CodeAuthInvalidToken   = 2002
	CodeAuthInvalidMTLS    = 2003
	CodeTenantSuspended    = 2005
	CodeForbidden          = 2007
	CodeProxyDuplicate     = 3001
	CodeProxyNotFound      = 3002
	CodeDomainBlacklisted  = 3004
	CodePortOutOfRange     = 3005
	CodeTypeNotEnabled     = 3006
	CodeLocalDialFailed    = 3007
	CodeQuotaTunnels       = 4001
	// CodeQuotaExceeded is the generic over-cap signal. Specific dim
	// codes (tunnels, online_clients) ride in the MessageKey instead so
	// the wire stays open to adding new dimensions without a code
	// proliferation. Edge sends this when the per-org max_online_clients
	// gate refuses a fresh handshake or when the periodic over-cap
	// sweeper evicts an existing session.
	CodeQuotaExceeded = 4002
	CodeRateLimited   = 4005
	CodeInternal      = 5001
	CodeNodeDraining  = 5003
)

// NewError is a convenience constructor used by both client and edge.
func NewError(code int, key, en string) *ErrorPayload {
	return &ErrorPayload{Code: code, MessageKey: key, MessageEN: en}
}

// ---- 0x01 HELLO --------------------------------------------------------

type HelloRequest struct {
	ProtocolMajor     uint32   `json:"protocol_major"`
	ProtocolMinor     uint32   `json:"protocol_minor"`
	ClientVersion     string   `json:"client_version,omitempty"`
	OS                string   `json:"os,omitempty"`
	Arch              string   `json:"arch,omitempty"`
	DeviceFingerprint []byte   `json:"device_fingerprint,omitempty"`
	Ts                int64    `json:"ts"`
	Nonce             []byte   `json:"nonce,omitempty"`
	Features          []string `json:"features,omitempty"`
}

// ---- 0x02 HELLO_ACK ----------------------------------------------------

type HelloAck struct {
	ProtocolMajor       uint32        `json:"protocol_major"`
	ProtocolMinor       uint32        `json:"protocol_minor"`
	ServerID            string        `json:"server_id"`
	Region              string        `json:"region,omitempty"`
	SuggestedTransport  TransportKind `json:"suggested_transport,omitempty"`
	Features            []string      `json:"features,omitempty"`
	HeartbeatIntervalMs uint32        `json:"heartbeat_interval_ms"`
	ConfigEpoch         uint64        `json:"config_epoch"`
}

// ---- 0x03 AUTH ---------------------------------------------------------

type AuthRequest struct {
	Token        string `json:"token,omitempty"`
	MTLSCertSPKI []byte `json:"mtls_cert_spki,omitempty"`
	OrgID        string `json:"org_id,omitempty"`
	WorkspaceID  string `json:"workspace_id,omitempty"`
	ClientName   string `json:"client_name,omitempty"`
	// DeviceID is the int64 clients.id returned by identity-svc.RegisterClient.
	// Optional and untrusted: the edge uses it only for live-presence tracking.
	// 0 = unknown.
	DeviceID int64 `json:"device_id,omitempty"`
}

// ---- 0x04 AUTH_RESP ----------------------------------------------------

type QuotaSnapshot struct {
	MaxTunnels        uint32   `json:"max_tunnels,omitempty"`
	MaxOnlineClients  uint32   `json:"max_online_clients,omitempty"`
	BandwidthBps      uint64   `json:"bandwidth_bps,omitempty"`
	MonthlyTrafficB   uint64   `json:"monthly_traffic_b,omitempty"`
	MonthlyUsedB      uint64   `json:"monthly_used_b,omitempty"`
	AllowedProxyTypes []string `json:"allowed_proxy_types,omitempty"`
	ExpiresAtMs       int64    `json:"expires_at_ms,omitempty"`
}

type AuthResponse struct {
	TenantID    string         `json:"tenant_id,omitempty"`
	WorkspaceID string         `json:"workspace_id,omitempty"`
	ClientID    string         `json:"client_id,omitempty"`
	SessionID   string         `json:"session_id,omitempty"`
	Quotas      *QuotaSnapshot `json:"quotas,omitempty"`
	// edge's BaseDomain (HTTPListener.BaseDomain in edge
	// config) — e.g. "localtest.me" in dev, "calabi.net" in prod. The
	// daemon uses it to render TCP/UDP public addrs as
	// `<base_domain>:<remote_port>` instead of dev's ugly
	// `localhost:<port>` (which is what snap.server_addr's host
	// resolves to when CALABI_SERVER points at the loopback).
	//
	// Multi-region note: every edge can advertise its own BaseDomain
	// since AUTH_RESP is per-session. If we later split tcp/http base
	// hosts (e.g. tcp.example.com vs *.example.com), add a separate
	// TCPHost field; for now BaseDomain works for both because tcp
	// traffic to <base>:<port> lands on the same edge IP.
	//
	// Old daemons ignore unknown JSON fields; old edges send "" and
	// the daemon falls back to snap.server_addr's host. Safe to roll
	// out asymmetrically.
	BaseDomain string `json:"base_domain,omitempty"`
	// HTTPPort / HTTPSPort are the edge's PUBLIC HTTP / HTTPS listener ports,
	// advertised so a self-hosted console can render a directly-usable URL
	// (`http://<domain>:<http_port>`) for non-standard ports. 0 = not advertised
	// (e.g. a platform edge behind a load balancer on 80/443) → fall back to the
	// bare domain. Old edges send 0; old daemons ignore the fields.
	HTTPPort  uint32        `json:"http_port,omitempty"`
	HTTPSPort uint32        `json:"https_port,omitempty"`
	Error     *ErrorPayload `json:"error,omitempty"`
}

// ---- 0x10 NEW_PROXY ----------------------------------------------------

type ProxyOptions struct {
	HTTPHostRewrite  string   `json:"http_host_rewrite,omitempty"`
	HTTPBasicAuthB64 string   `json:"http_basic_auth_b64,omitempty"`
	HTTPExtraHeaders string   `json:"http_extra_headers,omitempty"`
	IPWhitelist      []string `json:"ip_whitelist,omitempty"`
	BandwidthBps     uint64   `json:"bandwidth_bps,omitempty"`

	// SecurityConfigJSON carries a client-supplied security policy as a JSON
	// object matching the tunnel config_json `security` block (ip / basic_auth /
	// rate_limit / request_headers / oauth). The edge applies it ONLY when it
	// runs in standalone mode (top-level `mode: standalone`) AND no control plane
	// is wired — the self-hosted / open-source fork where the operator IS the
	// trust root. Managed and BYOI edges IGNORE this field and use the
	// server-authoritative config_json from the control plane, so a tampered
	// client can never self-grant or bypass the per-plan gate. Old edges ignore
	// this unknown JSON field. 2026-06-13.
	SecurityConfigJSON string `json:"security_config_json,omitempty"`
}

type NewProxyRequest struct {
	Name       string        `json:"name"`
	Type       ProxyKind     `json:"type"`
	LocalAddr  string        `json:"local_addr,omitempty"`
	Domain     string        `json:"domain,omitempty"`
	CertName   string        `json:"cert_name,omitempty"`
	RemotePort uint32        `json:"remote_port,omitempty"`
	Options    *ProxyOptions `json:"options,omitempty"`
	// ClaimTunnelID, when non-zero, asks the edge to update the existing
	// tunnel-svc row with this id (writing edge_node_id / domain / remote_port
	// onto it) instead of inserting a fresh row. Used by the daemon-mode
	// auto-claim path (Phase D): the console pre-created a tunnel with
	// edge_node_id=0; the client receives it via CONFIG_PUSH.UpsertProxies
	// and "claims" it without duplicating the row.
	//
	// Old edges that don't know this field will ignore it and fall back
	// to CreateTunnel — producing a duplicate row but not breaking the
	// session. Clients should only set this for tunnels they got from a
	// CONFIG_PUSH (where TunnelID is known and authoritative).
	ClaimTunnelID int64 `json:"claim_tunnel_id,omitempty"`
}

type NewProxyResponse struct {
	ProxyID    string        `json:"proxy_id,omitempty"`
	Domain     string        `json:"domain,omitempty"`
	RemotePort uint32        `json:"remote_port,omitempty"`
	TTLSeconds uint32        `json:"ttl_seconds,omitempty"`
	Error      *ErrorPayload `json:"error,omitempty"`
}

// ---- 0x12 CLOSE_PROXY --------------------------------------------------

type CloseProxyRequest struct {
	ProxyID string `json:"proxy_id"`
	Reason  string `json:"reason,omitempty"`
}

// ---- 0x20 NEW_CONN -----------------------------------------------------

type NewConnRequest struct {
	ProxyID      string `json:"proxy_id"`
	StreamID     uint64 `json:"stream_id"`
	VisitorIP    string `json:"visitor_ip,omitempty"`
	VisitorPort  uint32 `json:"visitor_port,omitempty"`
	OriginalHost string `json:"original_host,omitempty"`
	OriginalPath string `json:"original_path,omitempty"`
	InitialBytes []byte `json:"initial_bytes,omitempty"`
}

// ---- 0x21 CONN_ACK -----------------------------------------------------

type ConnAck struct {
	ProxyID  string        `json:"proxy_id"`
	StreamID uint64        `json:"stream_id"`
	Error    *ErrorPayload `json:"error,omitempty"`
}

// ---- 0x30 PING / 0x31 PONG ---------------------------------------------

type Ping struct {
	ClientSendNs  int64  `json:"client_send_ns"`
	BytesInDelta  uint64 `json:"bytes_in_delta,omitempty"`
	BytesOutDelta uint64 `json:"bytes_out_delta,omitempty"`
}

type Pong struct {
	ClientSendNs int64 `json:"client_send_ns"`
	ServerRecvNs int64 `json:"server_recv_ns"`
	ServerSendNs int64 `json:"server_send_ns"`
}

// ---- 0x40 CONFIG_PUSH --------------------------------------------------

// UpsertProxy describes one server-side tunnel that the client should
// register locally on receipt (Phase C). Mirrors the bits the existing
// NEW_PROXY flow uses, plus a server-assigned proxy_id so the client
// can skip the round-trip and just install the entry.
type UpsertProxy struct {
	ProxyID    string    `json:"proxy_id"`
	TunnelID   int64     `json:"tunnel_id,omitempty"`
	Name       string    `json:"name"`
	Type       ProxyKind `json:"type"`
	LocalAddr  string    `json:"local_addr,omitempty"`
	Domain     string    `json:"domain,omitempty"`
	RemotePort uint32    `json:"remote_port,omitempty"`
}

// ConfigPush is the runtime-config delta the edge pushes down to a
// connected client. only supported the `close_proxy_ids`
// branch; Phase C added `upsert_proxies` so the console can create a
// tunnel for a connected client and have it install locally without
// the user re-running calabi http.
//
// Backward compat: a client that doesn't know about upsert_proxies
// will simply ignore the field (json unmarshal is forgiving).
type ConfigPush struct {
	Epoch            uint64         `json:"epoch,omitempty"`
	Quotas           *QuotaSnapshot `json:"quotas,omitempty"`
	SuggestedEdge    string         `json:"suggested_edge,omitempty"`
	SuggestedAfterMs uint32         `json:"suggested_after_ms,omitempty"`
	CloseProxyIDs    []string       `json:"close_proxy_ids,omitempty"`
	CloseReason      *ErrorPayload  `json:"close_reason,omitempty"`
	UpsertProxies    []UpsertProxy  `json:"upsert_proxies,omitempty"`
	// FullSync, when true, tells the client "UpsertProxies is the
	// complete authoritative list of tunnels for you — reconcile your
	// local state to match." Set by the edge's post-handshake catch-up
	// push so the client can prune entries it accumulated across a
	// brief reconnect (during which one or more console-side deletes
	// fired CloseProxyIDs the client missed). Live deltas (single
	// upserts / deletes) leave it false. Backward-compat: pre-2026-05
	// edges/clients omit and default to false, preserving old behaviour.
	FullSync bool `json:"full_sync,omitempty"`
}

// ---- 0xF0 GO_AWAY ------------------------------------------------------

type GoAway struct {
	DrainDeadlineMs    uint32        `json:"drain_deadline_ms,omitempty"`
	SuggestedEdge      string        `json:"suggested_edge,omitempty"`
	SuggestedTransport TransportKind `json:"suggested_transport,omitempty"`
	Reason             string        `json:"reason,omitempty"`
}

// ---- helpers -----------------------------------------------------------

// Marshal encodes v into a frame payload. Returns ErrFrameTooLarge if the
// encoded bytes would exceed MaxPayloadSize.
func Marshal(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("protocol: marshal: %w", err)
	}
	if len(b) > MaxPayloadSize {
		return nil, ErrFrameTooLarge
	}
	return b, nil
}

// Unmarshal decodes a frame payload into v.
func Unmarshal(data []byte, v any) error {
	if len(data) == 0 {
		return nil // legal empty payload
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("protocol: unmarshal: %w", err)
	}
	return nil
}

// EncodePayload is a convenience that builds a Frame in one call. It does
// not set RequestID; the caller owns request-id allocation.
func EncodePayload(typ FrameType, payload any) (Frame, error) {
	b, err := Marshal(payload)
	if err != nil {
		return Frame{}, err
	}
	return Frame{Version: CurrentMajor, Type: typ, Payload: b}, nil
}
