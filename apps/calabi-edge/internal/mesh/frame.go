// Package mesh defines the edge↔edge intra-region forwarding wire format. When a visitor lands on an edge that does NOT own the requested
// tunnel, that edge ("relay") opens a VPC-internal connection to the edge
// that DOES own it ("owner") and replays the visitor's traffic through it.
//
// The forwarding connection starts with a small framing header so the owner
// edge knows how to route the relayed bytes:
//
//	[4]              magic            = "CMF1" (Calabi Mesh Forward v1)
//	[4]  BE          headerJSONLen
//	[headerJSONLen]  headerJSON       (ForwardHeader, sans head bytes)
//	[4]  BE          headLen
//	[headLen]        head             (sniffed HTTP request head / TLS ClientHello)
//	... then the live bidirectional visitor byte stream ...
//
// The owner edge does its OWN router lookup on Host (it is authoritative for
// which proxy currently serves that name), opens a yamux stream to the
// client, replays `head`, and splices the rest. Bytes are metered on the
// owner's session — the single source of truth for the customer's quota — so
// the relay edge never double-counts.
//
// Anti-loop: the forward LISTENER never re-forwards. A frame received on the
// peer-forward port is either served locally or rejected; it is never relayed
// onward. That structurally prevents forwarding loops even under a transient
// split-brain owner registry. OriginEdge is carried for logging only.
//
// Cross-region forwarding never happens: the owner registry and the edge
// address book are both region-scoped, so a relay only ever dials a
// same-region peer.
package mesh

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Magic identifies a v1 mesh-forward stream. Four ASCII bytes so a stray
// connection to the forward port (health check, port scanner) is rejected
// cheaply before we try to JSON-decode anything.
var magic = [4]byte{'C', 'M', 'F', '1'}

const (
	// frameVersion is the ForwardHeader.Version emitted by this build.
	frameVersion = 1

	// maxHeaderLen caps the JSON header. Generous — a header is a few
	// hundred bytes — but bounded so a malformed length prefix can't make
	// us allocate gigabytes.
	maxHeaderLen = 64 * 1024
	// maxHeadLen caps the replayed sniff buffer. The HTTP listener caps its
	// head at 16 KiB and the SNI listener peeks at most 4 KiB, so 64 KiB is
	// well above any legitimate value.
	maxHeadLen = 64 * 1024
)

// Kind enumerates the visitor-listener kinds that support mesh forwarding.
// TCP/UDP are intentionally excluded in v1 (raw L4 has no host key to route
// a relayed conn by).
const (
	KindHTTP  = "http"
	KindHTTPS = "https"
	KindSNI   = "sni"
)

// ForwardHeader is the JSON-encoded routing header at the head of a
// mesh-forward connection. It carries everything the owner edge needs to
// reconstruct the visitor's NewConnRequest EXCEPT the sniffed head bytes,
// which follow as a separate length-prefixed binary blob (binary-safe).
type ForwardHeader struct {
	Version int    `json:"v"`
	Kind    string `json:"kind"`           // KindHTTP | KindHTTPS | KindSNI
	Host    string `json:"host"`           // routing key: HTTP Host / TLS SNI
	Path    string `json:"path,omitempty"` // original request path (HTTP only, informational)

	VisitorIP   string `json:"visitor_ip,omitempty"`
	VisitorPort uint32 `json:"visitor_port,omitempty"`

	// OriginEdge is the edge_node_id of the relaying edge. Logging /
	// debugging only — routing is by Host, not by this field.
	OriginEdge int64 `json:"origin_edge,omitempty"`
}

// ValidKind reports whether k is a forwarding-capable listener kind.
func ValidKind(k string) bool {
	switch k {
	case KindHTTP, KindHTTPS, KindSNI:
		return true
	default:
		return false
	}
}

// WriteFrame emits the magic + header + head prefix onto w. After this
// returns the caller splices the live visitor stream onto the same conn.
func WriteFrame(w io.Writer, h ForwardHeader, head []byte) error {
	if !ValidKind(h.Kind) {
		return fmt.Errorf("mesh: invalid kind %q", h.Kind)
	}
	if len(head) > maxHeadLen {
		return fmt.Errorf("mesh: head too large (%d > %d)", len(head), maxHeadLen)
	}
	h.Version = frameVersion
	hdr, err := json.Marshal(h)
	if err != nil {
		return fmt.Errorf("mesh: marshal header: %w", err)
	}
	if len(hdr) > maxHeaderLen {
		return fmt.Errorf("mesh: header too large (%d > %d)", len(hdr), maxHeaderLen)
	}

	// Assemble into a single buffer so we issue one Write — keeps the
	// prefix atomic on the wire and avoids partial-frame interleaving.
	buf := make([]byte, 0, 4+4+len(hdr)+4+len(head))
	buf = append(buf, magic[:]...)
	buf = appendUint32(buf, uint32(len(hdr)))
	buf = append(buf, hdr...)
	buf = appendUint32(buf, uint32(len(head)))
	buf = append(buf, head...)

	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("mesh: write frame: %w", err)
	}
	return nil
}

// ReadFrame consumes the magic + header + head prefix from r and returns the
// decoded header plus the head bytes. The caller then splices the remaining
// bytes on r as the live visitor stream.
//
// r SHOULD be buffered by the caller (a *bufio.Reader) so the post-frame
// splice reads from the same buffered source without losing bytes.
func ReadFrame(r io.Reader) (ForwardHeader, []byte, error) {
	var m [4]byte
	if _, err := io.ReadFull(r, m[:]); err != nil {
		return ForwardHeader{}, nil, fmt.Errorf("mesh: read magic: %w", err)
	}
	if m != magic {
		return ForwardHeader{}, nil, errors.New("mesh: bad magic (not a forward stream)")
	}

	hdrLen, err := readUint32(r)
	if err != nil {
		return ForwardHeader{}, nil, fmt.Errorf("mesh: read header len: %w", err)
	}
	if hdrLen == 0 || hdrLen > maxHeaderLen {
		return ForwardHeader{}, nil, fmt.Errorf("mesh: implausible header len %d", hdrLen)
	}
	hdrBuf := make([]byte, hdrLen)
	if _, err := io.ReadFull(r, hdrBuf); err != nil {
		return ForwardHeader{}, nil, fmt.Errorf("mesh: read header: %w", err)
	}
	var h ForwardHeader
	if err := json.Unmarshal(hdrBuf, &h); err != nil {
		return ForwardHeader{}, nil, fmt.Errorf("mesh: decode header: %w", err)
	}
	if !ValidKind(h.Kind) {
		return ForwardHeader{}, nil, fmt.Errorf("mesh: invalid kind %q", h.Kind)
	}

	headLen, err := readUint32(r)
	if err != nil {
		return ForwardHeader{}, nil, fmt.Errorf("mesh: read head len: %w", err)
	}
	if headLen > maxHeadLen {
		return ForwardHeader{}, nil, fmt.Errorf("mesh: implausible head len %d", headLen)
	}
	head := make([]byte, headLen)
	if headLen > 0 {
		if _, err := io.ReadFull(r, head); err != nil {
			return ForwardHeader{}, nil, fmt.Errorf("mesh: read head: %w", err)
		}
	}
	return h, head, nil
}

func appendUint32(b []byte, v uint32) []byte {
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], v)
	return append(b, tmp[:]...)
}

func readUint32(r io.Reader) (uint32, error) {
	var tmp [4]byte
	if _, err := io.ReadFull(r, tmp[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(tmp[:]), nil
}
