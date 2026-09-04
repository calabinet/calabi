package relay

import (
	"sort"
	"sync/atomic"

	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// Relay usage accounting (F2).
//
// Why it exists: relayed mesh traffic is, today, bandwidth the platform pays for
// and nobody counts. Until it is counted, "run your own relay and it's your own
// bandwidth" is a claim we cannot back — the platform's relays don't charge for
// anything either.
//
// What the relay knows, and deliberately no more: bytes per NODE KEY. It has no
// concept of an org and is not going to acquire one — resolving a key to a
// meshnet is the coordinator's job, and keeping that resolution out of the relay
// is what lets the same binary run on a user's VPS with nothing to phone home
// to. A relay reports opaque keys; the control plane decides whose they are.
//
// BOTH directions are reported and NEITHER is halved here. One relayed packet
// shows up twice — as the sender's In and the receiver's Out — and since both
// ends of a meshnet link belong to the same org, summing the two would bill it
// twice. Choosing the billing formula (egress is the closest match to what the
// platform actually pays for) is a control-plane decision that must be able to
// change without redeploying a fleet of relays, so the relay reports facts and
// makes no judgement.
//
// Counts are ciphertext bytes: framing (5-byte header + 32-byte key) and the
// TCP/IP overhead underneath are not included, so this reads slightly under what
// the NIC bills.

// usageCounter is one node's running byte totals. Held by pointer on the client
// so the forwarding path never has to look anything up, and kept in the hub's
// map so bytes survive the connection that produced them.
type usageCounter struct {
	in  atomic.Uint64 // bytes the relay RECEIVED from this node
	out atomic.Uint64 // bytes the relay SENT to this node
	// meshnet is the org this node belongs to, taken from the R0' grant it proved
	// (auth.go). It is the ONE thing that lets a multi-tenant platform relay say
	// whose bytes it forwarded — the relay is otherwise org-blind. Zero when auth
	// is off (no grant presented), in which case the bytes are unattributable and
	// a platform reporter drops them rather than misbill. Atomic because it is set
	// under the hub lock in add() but also refreshed WITHOUT it when a live link
	// re-authenticates (acceptProof), while TakeUsage reads it under the lock.
	meshnet atomic.Int64
}

// UsageDelta is one node's traffic since the last Take. Meshnet rides along so a
// per-org reporter can attribute the bytes without the relay having to resolve
// anything itself; it is 0 when the relay ran with auth off.
type UsageDelta struct {
	Key      meshproto.NodeKey `json:"key"`
	Meshnet  int64             `json:"meshnet"`
	BytesIn  uint64            `json:"bytes_in"`
	BytesOut uint64            `json:"bytes_out"`
}

// counterFor returns the node's counter, creating it on first use. Called under
// h.mu from add().
func (h *Hub) counterFor(key meshproto.NodeKey) *usageCounter {
	if h.usage == nil {
		h.usage = make(map[meshproto.NodeKey]*usageCounter)
	}
	c, ok := h.usage[key]
	if !ok {
		c = &usageCounter{}
		h.usage[key] = c
	}
	return c
}

// TakeUsage returns every node's traffic since the previous call and resets the
// counters. Read-and-reset rather than a cumulative gauge so a reporter can send
// deltas; a reporter whose send fails is expected to hold the delta and merge it
// into the next one, because these bytes exist nowhere else.
//
// Counters for nodes that are no longer connected are dropped once drained, so a
// long-lived relay's map tracks live nodes rather than every node it ever saw. A
// still-connected node keeps its counter — the client holds a pointer to it, and
// deleting the entry underneath would send its next bytes into an orphan.
//
// Deletion is one cycle BEHIND the drain, which is not an oversight: forward()
// reaches the counter through a pointer after releasing the hub lock, so an
// entry that just yielded bytes may still receive more. Only dropping it once it
// drains empty gives those in-flight bytes somewhere to land.
func (h *Hub) TakeUsage() []UsageDelta {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]UsageDelta, 0, len(h.usage))
	for key, c := range h.usage {
		in, eg := c.in.Swap(0), c.out.Swap(0)
		if in != 0 || eg != 0 {
			out = append(out, UsageDelta{Key: key, Meshnet: c.meshnet.Load(), BytesIn: in, BytesOut: eg})
			continue
		}
		if h.clients[key] == nil {
			delete(h.usage, key)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Key.String() < out[j].Key.String()
	})
	return out
}
