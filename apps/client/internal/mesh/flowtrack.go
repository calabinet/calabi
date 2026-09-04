package mesh

import (
	"net/netip"
	"sync"
	"time"
)

// Reply tracking for the inbound packet filter (MESH.5b).
//
// The coordinator compiles a node's filter from the rules that name it as a
// DESTINATION. That alone is not a working firewall: a machine that only ever
// appears as a rule's SOURCE gets zero rules, and an empty enabled filter denies
// everything — including the SYN-ACK for the connection it just opened. Under
// the rule
//
//	{"src": ["tag:laptop"], "dst": ["tag:server"], "ports": ["22"]}
//
// the laptop can send to server:22 and then drops the server's reply, so nothing
// works at all. Every realistic ACL has that shape; only the wide-open
// {src:*, dst:*} default hides it.
//
// So the filter needs the one piece of state a stateless matcher cannot have:
// what THIS machine started. An outbound packet records its flow; an inbound
// packet that is the exact reverse of a recorded flow is admitted regardless of
// the rules. This is the standard conntrack "established" allowance, and it is
// what makes "only what a rule names may ARRIVE UNSOLICITED" the actual
// meaning of the filter.
//
// It is deliberately narrow: the match is the full 5-tuple reversed, so it
// admits the other end of a conversation we opened and nothing else. A peer we
// once contacted cannot use it to reach a different port.

// flowKey identifies one conversation from THIS machine's point of view, so the
// outbound and inbound halves produce the same key.
type flowKey struct {
	proto      uint8
	local      netip.Addr
	remote     netip.Addr
	localPort  uint16
	remotePort uint16
}

// Idle lifetimes, mirroring conntrack norms rather than inventing new ones: a
// TCP conversation may sit quiet between keystrokes, a UDP exchange is usually
// request/response, and ICMP is one round trip.
//
// These bound how long a reply stays welcome after the last packet in EITHER
// direction. A flow quieter than its lifetime falls back to the rules — which is
// the right answer for a machine that wants durable inbound reachability: give
// it a rule instead of relying on a conversation it started hours ago.
const (
	flowTTLTCP   = 60 * time.Minute
	flowTTLUDP   = 2 * time.Minute
	flowTTLOther = 60 * time.Second
	// maxFlows caps the table. Reached only under something pathological (a port
	// scan from this machine); the sweep below keeps it honest without making
	// packet handling allocate.
	maxFlows = 8192
)

func flowTTL(proto uint8) time.Duration {
	switch proto {
	case protoTCP:
		return flowTTLTCP
	case protoUDP:
		return flowTTLUDP
	default:
		return flowTTLOther
	}
}

// flowTable remembers conversations this machine started. Safe for concurrent
// use: the tun's read and write paths run on different goroutines.
type flowTable struct {
	mu   sync.Mutex
	seen map[flowKey]time.Time // value = expiry
	// now is overridable in tests; nil means time.Now.
	now func() time.Time
}

func newFlowTable() *flowTable {
	return &flowTable{seen: make(map[flowKey]time.Time)}
}

func (f *flowTable) clock() time.Time {
	if f.now != nil {
		return f.now()
	}
	return time.Now()
}

// observeOutbound records (or refreshes) the flow an outbound packet belongs to.
// Fragments and packets we could not parse carry no ports; they are recorded
// with port 0, which only ever matches another port-less packet of the same
// protocol between the same hosts.
func (f *flowTable) observeOutbound(t tuple) {
	k := flowKey{proto: t.proto, local: t.src, remote: t.dst, localPort: t.srcPort, remotePort: t.dstPort}
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.clock()
	if len(f.seen) >= maxFlows {
		f.sweepLocked(now)
	}
	if _, exists := f.seen[k]; !exists && len(f.seen) >= maxFlows {
		// Still full of live flows: refuse to grow rather than evict something
		// that is carrying traffic. The rules still apply, so this degrades to
		// "no established allowance", never to "allow everything".
		return
	}
	f.seen[k] = now.Add(flowTTL(t.proto))
}

// isReply reports whether an inbound packet is the other half of a conversation
// this machine started, refreshing the flow when it is.
func (f *flowTable) isReply(t tuple) bool {
	k := flowKey{proto: t.proto, local: t.dst, remote: t.src, localPort: t.dstPort, remotePort: t.srcPort}
	f.mu.Lock()
	defer f.mu.Unlock()
	exp, ok := f.seen[k]
	if !ok {
		return false
	}
	now := f.clock()
	if now.After(exp) {
		delete(f.seen, k)
		return false
	}
	f.seen[k] = now.Add(flowTTL(t.proto))
	return true
}

// sweepLocked drops expired entries. Caller holds the lock.
func (f *flowTable) sweepLocked(now time.Time) {
	for k, exp := range f.seen {
		if now.After(exp) {
			delete(f.seen, k)
		}
	}
}

// len is for tests and status reporting.
func (f *flowTable) len() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.seen)
}
