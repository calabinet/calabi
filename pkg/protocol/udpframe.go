// UDP datagram framing for in-stream transport.
//
// The wire encoding is intentionally minimal: a 2-byte big-endian length
// followed by that many payload bytes. One datagram per frame; no flags,
// no sequence number, no checksum. Yamux already provides reliable,
// ordered, multiplexed bytes — anything more is duplication.
//
//	+---+---+--------------------------------+
//	|  len  |          datagram bytes        |
//	+---+---+--------------------------------+
//	 2 bytes              0.65535
//
// Maximum payload is 65535 bytes; IPv4 UDP is capped at 65507 in practice,
// so the field is wide enough. The 0-length case is permitted as a
// keep-alive / flush marker (writer side may emit, reader side ignores).
//
// One conntrack flow per yamux stream: the same stream is reused for
// every datagram in (visitor_ip, visitor_port) → upstream until idle GC
// or the visitor stops sending. Source-NAT happens at the edge by
// remembering which UDPAddr opened which stream; the client never sees
// the visitor's IP.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// MaxUDPDatagram is the largest single datagram the framer can carry.
// Equals the 2-byte length field's max.
const MaxUDPDatagram = 65535

// ErrUDPFrameTruncated is returned if the framed length exceeds what the
// reader is willing to accept (defensive against framing corruption).
var ErrUDPFrameTruncated = errors.New("protocol: udp frame truncated")

// WriteUDPDatagram encodes one datagram into the framing above.
//
// The write is atomic at the framer level (header+payload in a single
// call) but not at the OS level — callers MUST serialize writes to the
// underlying stream if multiple goroutines may write concurrently.
func WriteUDPDatagram(w io.Writer, data []byte) error {
	if len(data) > MaxUDPDatagram {
		return fmt.Errorf("protocol: udp datagram too large (%d > %d)", len(data), MaxUDPDatagram)
	}
	buf := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(data)))
	copy(buf[2:], data)
	_, err := w.Write(buf)
	return err
}

// ReadUDPDatagram reads one framed datagram into dst, allocating an
// appropriately-sized slice. Returns io.EOF cleanly when the stream
// closes between frames; returns ErrUDPFrameTruncated if the stream
// closes mid-frame.
func ReadUDPDatagram(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		// io.EOF / io.ErrUnexpectedEOF surface unchanged so the caller
		// can distinguish "clean close" from "mid-header truncation".
		return nil, err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	if n == 0 {
		return nil, nil // keep-alive
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrUDPFrameTruncated
		}
		return nil, err
	}
	return buf, nil
}
