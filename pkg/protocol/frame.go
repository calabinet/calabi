package protocol

import (
	"encoding/binary"
	"errors"
	"io"
)

// EncodeHeader serializes f's header fields into the first HeaderSize bytes
// of dst, returning an error if dst is too small or the frame is invalid.
//
// The payload is NOT copied -- callers concatenate it afterward (or use
// WriteFrame which handles both).
func EncodeHeader(dst []byte, f Frame) error {
	if len(dst) < HeaderSize {
		return io.ErrShortBuffer
	}
	if len(f.Payload) > MaxPayloadSize {
		return ErrFrameTooLarge
	}
	binary.BigEndian.PutUint16(dst[0:2], Magic)
	dst[2] = f.Version
	dst[3] = uint8(f.Type)
	binary.BigEndian.PutUint32(dst[4:8], uint32(len(f.Payload)))
	binary.BigEndian.PutUint64(dst[8:16], f.RequestID)
	return nil
}

// DecodeHeader parses the first HeaderSize bytes of src into a Frame
// (payload nil). It validates Magic and Length but NOT Version (caller
// runs the negotiation against its supported set) and not Type.
//
// On success the second return value is the declared payload length so
// the caller knows how many more bytes to read.
func DecodeHeader(src []byte) (Frame, int, error) {
	if len(src) < HeaderSize {
		return Frame{}, 0, ErrShortHeader
	}
	if binary.BigEndian.Uint16(src[0:2]) != Magic {
		return Frame{}, 0, ErrBadMagic
	}
	length := binary.BigEndian.Uint32(src[4:8])
	if length > MaxPayloadSize {
		return Frame{}, 0, ErrFrameTooLarge
	}
	f := Frame{
		Version:   src[2],
		Type:      FrameType(src[3]),
		RequestID: binary.BigEndian.Uint64(src[8:16]),
	}
	return f, int(length), nil
}

// MarshalFrame returns a single contiguous byte slice containing the
// encoded header followed by the payload.
//
// Useful for stream transports where one Write call per frame is desired.
func MarshalFrame(f Frame) ([]byte, error) {
	if len(f.Payload) > MaxPayloadSize {
		return nil, ErrFrameTooLarge
	}
	buf := make([]byte, HeaderSize+len(f.Payload))
	if err := EncodeHeader(buf, f); err != nil {
		return nil, err
	}
	copy(buf[HeaderSize:], f.Payload)
	return buf, nil
}

// UnmarshalFrame is the inverse of MarshalFrame. It expects exactly one
// frame in src and returns an error if src has trailing bytes.
//
// For stream parsing prefer ReadFrame.
func UnmarshalFrame(src []byte) (Frame, error) {
	f, n, err := DecodeHeader(src)
	if err != nil {
		return Frame{}, err
	}
	if len(src) < HeaderSize+n {
		return Frame{}, ErrShortPayload
	}
	if len(src) > HeaderSize+n {
		return Frame{}, errors.New("protocol: trailing bytes after frame")
	}
	if n > 0 {
		// Copy so the returned slice is independent of src's backing array.
		f.Payload = make([]byte, n)
		copy(f.Payload, src[HeaderSize:HeaderSize+n])
	}
	return f, nil
}

// WriteFrame writes one frame to w using a single Write call so the header
// and payload are not split across multiple TCP/QUIC segments.
//
// Returns the total number of bytes written and any error from w.Write.
func WriteFrame(w io.Writer, f Frame) (int, error) {
	buf, err := MarshalFrame(f)
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

// ReadFrame reads exactly one frame from r. It performs two reads: one of
// HeaderSize bytes, then one of Length bytes. Use a buffered reader if r
// is unbuffered to avoid syscall churn on small frames.
func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [HeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return Frame{}, ErrShortHeader
		}
		return Frame{}, err
	}
	f, n, err := DecodeHeader(hdr[:])
	if err != nil {
		return Frame{}, err
	}
	if n > 0 {
		f.Payload = make([]byte, n)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return Frame{}, ErrShortPayload
			}
			return Frame{}, err
		}
	}
	return f, nil
}
