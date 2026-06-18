package protocol

import "errors"

// Codec-level errors. Wire-protocol error codes (CODE_*) live in
// proto/calabi/v1/errors.proto and are carried inside Error payloads.
var (
	// ErrBadMagic is returned when a frame begins with bytes other than
	// the protocol's two-byte magic constant.
	ErrBadMagic = errors.New("protocol: bad magic")

	// ErrUnsupportedVersion is returned for frames whose Ver byte cannot
	// be negotiated against this implementation's supported set.
	ErrUnsupportedVersion = errors.New("protocol: unsupported version")

	// ErrFrameTooLarge is returned when the Length field exceeds the
	// MaxPayloadSize cap.
	ErrFrameTooLarge = errors.New("protocol: frame too large")

	// ErrShortHeader is returned when fewer than HeaderSize bytes are
	// available where a header was expected.
	ErrShortHeader = errors.New("protocol: short header")

	// ErrShortPayload is returned when fewer bytes than Length were
	// readable for a payload.
	ErrShortPayload = errors.New("protocol: short payload")
)
