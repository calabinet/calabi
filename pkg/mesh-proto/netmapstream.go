package meshproto

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"sort"
	"sync"

	"github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// NetMapEncoder retains fingerprints, never another complete peer graph. One
// encoder belongs to one authenticated RPC stream; discard it on disconnect.
type NetMapEncoder struct {
	seq      uint64
	peers    map[int64][32]byte
	metadata [32]byte
}

func mapDigest(m proto.Message) ([32]byte, error) {
	b, err := (proto.MarshalOptions{Deterministic: true}).Marshal(m)
	return sha256.Sum256(b), err
}

// PeerFingerprintCache memoizes only public peer contents. It must be scoped to
// one immutable group snapshot, never to authorization results or relay grants.
// Equality against an owned copy also covers live declarations and expiry: a
// changed message cannot reuse a stale fingerprint, even with the same node ID.
// The fixed entry limit bounds retention; overflow simply hashes uncached.
type PeerFingerprintCache struct {
	mu      sync.Mutex
	peers   map[int64]peerFingerprint
	scratch []byte
	bytes   int
}
type peerFingerprint struct {
	wire []byte
	hash [32]byte
}

func (c *PeerFingerprintCache) digest(p *meshpb.Peer) ([32]byte, error) {
	if c == nil {
		return mapDigest(p)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	b, err := (proto.MarshalOptions{Deterministic: true}).MarshalAppend(c.scratch[:0], p)
	if cap(b) <= 65536 {
		c.scratch = b[:0]
	} else {
		c.scratch = nil
	}
	if err == nil {
		if old, ok := c.peers[p.NodeId]; ok && bytes.Equal(old.wire, b) {
			return old.hash, nil
		}
	}
	h := sha256.Sum256(b)
	oldSize := len(c.peers[p.NodeId].wire)
	if err == nil && (len(c.peers) < 4096 || oldSize != 0) && c.bytes-oldSize+len(b) <= 8<<20 {
		if c.peers == nil {
			c.peers = make(map[int64]peerFingerprint)
		}
		c.peers[p.NodeId] = peerFingerprint{append([]byte(nil), b...), h}
		c.bytes += len(b) - oldSize
	}
	return h, err
}

// mapMetadata shallow-copies only through protobuf reflection, so protobuf's
// internal mutex is never copied. Inputs and nested messages remain read-only.
func mapMetadata(m *meshpb.NetMap) *meshpb.NetMap {
	out := &meshpb.NetMap{}
	m.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		n := fd.Number()
		if n != 2 && n != 6 && (n < 20 || n > 25) {
			out.ProtoReflect().Set(fd, v)
		}
		return true
	})
	out.ProtoReflect().SetUnknown(append([]byte(nil), m.ProtoReflect().GetUnknown()...))
	return out
}

// Next is transactional: install the returned encoder ONLY after Send succeeds.
// Upserts are whole peers. Metadata replacement covers empty/zero fields too,
// so removals and ACL tightening cannot retain an earlier permission.
func (e NetMapEncoder) Next(full *meshpb.NetMap) (*meshpb.NetMap, NetMapEncoder, error) {
	return e.NextWithPeerCache(full, nil)
}

// NextWithPeerCache has the same transactional semantics as Next. The cache
// shares content fingerprints only; each stream still derives its own delta.
func (e NetMapEncoder) NextWithPeerCache(full *meshpb.NetMap, cache *PeerFingerprintCache) (*meshpb.NetMap, NetMapEncoder, error) {
	if full == nil || full.Self == nil {
		return nil, e, errors.New("netmap missing self")
	}
	next := NetMapEncoder{seq: e.seq + 1, peers: make(map[int64][32]byte, len(full.Peers))}
	meta := mapMetadata(full)
	var err error
	next.metadata, err = mapDigest(meta)
	if err != nil {
		return nil, e, err
	}
	changed := make([]*meshpb.Peer, 0)
	for _, p := range full.Peers {
		if p == nil || p.NodeId <= 0 {
			return nil, e, errors.New("invalid peer id")
		}
		if _, ok := next.peers[p.NodeId]; ok {
			return nil, e, errors.New("duplicate peer id")
		}
		h, err := cache.digest(p)
		if err != nil {
			return nil, e, err
		}
		next.peers[p.NodeId] = h
		if old, ok := e.peers[p.NodeId]; !ok || old != h {
			changed = append(changed, p)
		}
	}
	removed := make([]int64, 0)
	for id := range e.peers {
		if _, ok := next.peers[id]; !ok {
			removed = append(removed, id)
		}
	}
	sort.Slice(removed, func(i, j int) bool { return removed[i] < removed[j] })
	sort.Slice(changed, func(i, j int) bool { return changed[i].NodeId < changed[j].NodeId })
	if e.seq == 0 {
		meta.Peers, meta.RelayGrant, meta.Sequence = full.Peers, full.RelayGrant, next.seq
		return meta, next, nil
	}
	delta := &meshpb.NetMap{}
	if e.metadata != next.metadata {
		delta = meta
		delta.MetadataPresent = true
	}
	delta.Sequence, delta.BaseSequence, delta.Delta = next.seq, e.seq, true
	delta.Peers, delta.RemovedPeerIds, delta.RelayGrant = changed, removed, full.RelayGrant
	delta.GrantOnly = !delta.MetadataPresent && len(changed) == 0 && len(removed) == 0
	// Delay the second metadata object until a full fallback is actually needed.
	// full has no envelope; compute the exact sequence tag+varint size.
	seqSize := 1
	for v := next.seq; v >= 128; v >>= 7 {
		seqSize++
	}
	if proto.Size(delta) < proto.Size(full)+2+seqSize {
		return delta, next, nil
	}
	out := mapMetadata(full)
	out.Peers, out.RelayGrant, out.Sequence = full.Peers, full.RelayGrant, next.seq
	return out, next, nil
}

// NetMapDecoder validates a complete frame before changing its baseline. A
// mismatch is fatal to this stream: reopen PullNetMap for an initial full map.
// Returned protobufs are read-only, valid until this decoder is discarded.
type NetMapDecoder struct {
	current *meshpb.NetMap
	seq     uint64
}

func (d *NetMapDecoder) Apply(frame *meshpb.NetMap) (*meshpb.NetMap, bool, error) {
	bad := func() (*meshpb.NetMap, bool, error) {
		return nil, false, errors.New("invalid netmap sequence or delta; reconnect for full snapshot")
	}
	if frame == nil {
		return bad()
	}
	if !frame.Delta {
		if frame.BaseSequence != 0 || frame.GrantOnly || frame.MetadataPresent || len(frame.RemovedPeerIds) != 0 || frame.Self == nil {
			return bad()
		}
		if d.current != nil && (frame.Sequence == 0 && d.seq != 0 || frame.Sequence != 0 && frame.Sequence != d.seq+1) {
			return bad()
		}
		if d.current == nil && frame.Sequence > 1 {
			return bad()
		}
	} else if d.current == nil || frame.Sequence == 0 || frame.BaseSequence != d.seq || frame.Sequence != d.seq+1 || (frame.GrantOnly && (frame.MetadataPresent || len(frame.Peers) != 0 || len(frame.RemovedPeerIds) != 0)) {
		return bad()
	}
	if frame.Delta && !frame.MetadataPresent && proto.Size(mapMetadata(frame)) != 0 {
		return bad()
	}
	if d.current != nil && frame.Self != nil && (frame.Self.NodeId != d.current.Self.NodeId || frame.Self.NodeKey != d.current.Self.NodeKey) {
		return bad()
	}
	if frame.Delta && frame.MetadataPresent && frame.Self == nil {
		return bad()
	}
	if frame.GrantOnly {
		out := mapMetadata(d.current)
		out.Peers = d.current.Peers
		out.RelayGrant = append([]byte(nil), frame.RelayGrant...)
		out.Sequence = frame.Sequence
		d.current, d.seq = out, frame.Sequence
		return out, true, nil
	}
	var out *meshpb.NetMap
	if !frame.Delta || frame.MetadataPresent {
		out = mapMetadata(frame)
	} else {
		out = mapMetadata(d.current)
	}
	// Validate sorted copies, then merge without rebuilding two hash tables and
	// sorting the complete retained graph on every small delta. Never mutate an
	// earlier frame or publish a partial result on malformed input.
	upserts := append([]*meshpb.Peer(nil), frame.Peers...)
	for _, p := range upserts {
		if p == nil || p.NodeId <= 0 {
			return bad()
		}
	}
	sort.Slice(upserts, func(i, j int) bool { return upserts[i].NodeId < upserts[j].NodeId })
	for i := 1; i < len(upserts); i++ {
		if upserts[i-1].NodeId == upserts[i].NodeId {
			return bad()
		}
	}
	removed := append([]int64(nil), frame.RemovedPeerIds...)
	sort.Slice(removed, func(i, j int) bool { return removed[i] < removed[j] })
	for i, id := range removed {
		if id <= 0 || (i > 0 && removed[i-1] == id) {
			return bad()
		}
		j := sort.Search(len(upserts), func(j int) bool { return upserts[j].NodeId >= id })
		if j < len(upserts) && upserts[j].NodeId == id {
			return bad()
		}
		j = sort.Search(len(d.current.Peers), func(j int) bool { return d.current.Peers[j].NodeId >= id })
		if j == len(d.current.Peers) || d.current.Peers[j].NodeId != id {
			return bad()
		}
	}
	if !frame.Delta {
		out.Peers = upserts
	} else {
		out.Peers = make([]*meshpb.Peer, 0, len(d.current.Peers)+len(upserts)-len(removed))
		j, r := 0, 0
		for _, old := range d.current.Peers {
			for j < len(upserts) && upserts[j].NodeId < old.NodeId {
				out.Peers = append(out.Peers, upserts[j])
				j++
			}
			if r < len(removed) && removed[r] == old.NodeId {
				r++
				continue
			}
			if j < len(upserts) && upserts[j].NodeId == old.NodeId {
				out.Peers = append(out.Peers, upserts[j])
				j++
			} else {
				out.Peers = append(out.Peers, old)
			}
		}
		out.Peers = append(out.Peers, upserts[j:]...)
	}
	out.RelayGrant = append([]byte(nil), frame.RelayGrant...)
	out.Sequence = frame.Sequence
	d.current, d.seq = out, frame.Sequence
	return out, frame.GrantOnly, nil
}
