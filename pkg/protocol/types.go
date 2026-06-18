package protocol

// Constants for the Calabi wire framing.
const (
	// Magic is the two-byte sentinel that begins every frame: ASCII "TX".
	Magic uint16 = 0x5458

	// CurrentMajor is the protocol major version implemented by this package.
	CurrentMajor uint8 = 1

	// HeaderSize is the fixed serialized length of a frame header in bytes.
	HeaderSize = 16

	// MaxPayloadSize is the largest legal payload (Length field) per spec
	MaxPayloadSize = 16 * 1024 * 1024 // 16 MiB
)

// FrameType is the 1-byte frame type tag carried in the header.
// Mirrors the FrameType enum in proto/calabi/v1/control.proto.
type FrameType uint8

// Frame type constants. Keep in sync with control.proto.
const (
	FrameUnspecified   FrameType = 0x00
	FrameHello         FrameType = 0x01
	FrameHelloAck      FrameType = 0x02
	FrameAuth          FrameType = 0x03
	FrameAuthResp      FrameType = 0x04
	FrameNewProxy      FrameType = 0x10
	FrameNewProxyResp  FrameType = 0x11
	FrameCloseProxy    FrameType = 0x12
	FrameNewConn       FrameType = 0x20
	FrameConnAck       FrameType = 0x21
	FramePing          FrameType = 0x30
	FramePong          FrameType = 0x31
	FrameConfigPush    FrameType = 0x40
	FrameMetricsReport FrameType = 0x50
	FrameGoAway        FrameType = 0xF0
	FrameError         FrameType = 0xFF
)

// String renders a FrameType for logging.
func (t FrameType) String() string {
	switch t {
	case FrameUnspecified:
		return "UNSPECIFIED"
	case FrameHello:
		return "HELLO"
	case FrameHelloAck:
		return "HELLO_ACK"
	case FrameAuth:
		return "AUTH"
	case FrameAuthResp:
		return "AUTH_RESP"
	case FrameNewProxy:
		return "NEW_PROXY"
	case FrameNewProxyResp:
		return "NEW_PROXY_RESP"
	case FrameCloseProxy:
		return "CLOSE_PROXY"
	case FrameNewConn:
		return "NEW_CONN"
	case FrameConnAck:
		return "CONN_ACK"
	case FramePing:
		return "PING"
	case FramePong:
		return "PONG"
	case FrameConfigPush:
		return "CONFIG_PUSH"
	case FrameMetricsReport:
		return "METRICS_REPORT"
	case FrameGoAway:
		return "GO_AWAY"
	case FrameError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// IsKnown reports whether t is a registered frame type. Unknown types must
// be tolerated per the forward-compat rule in spec
func (t FrameType) IsKnown() bool {
	return t.String() != "UNKNOWN" && t != FrameUnspecified
}

// Frame is a decoded Calabi frame. Payload is the raw protobuf bytes;
// callers do their own marshaling.
type Frame struct {
	Version   uint8
	Type      FrameType
	RequestID uint64
	Payload   []byte
}
