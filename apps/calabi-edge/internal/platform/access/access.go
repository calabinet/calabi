// Package access aggregates "who connected to which tunnel" at the edge and
// publishes it for metering-svc to store.
//
// WHY THE EDGE AND NOT THE CLIENT. The mesh side of this product had to take
// its connection records from the client, because nothing else can see a
// direct peer-to-peer flow — and it pays for that with a disclaimer, since a
// compromised machine can under-report itself.
// A tunnel has no such problem: every visitor byte crosses a platform edge, so
// the edge sees all of it and the client is not consulted at all. This trail is
// evidence, not testimony.
//
// (A BYOI self-hosted edge is the customer's own VPS, so its reports are the
// customer's own machine describing traffic to the customer's own service.
// Still not a third party, and still not the CLIENT — a daemon that wanted to
// hide its visitors cannot.)
//
// WHAT IS RECORDED, AND WHY THE VISITOR IP IS IN IT. Mesh deliberately keeps
// no endpoint addresses: a peer's public IP over time is a LOCATION trail of
// one of our users' own machines. A tunnel visitor is the opposite
// case — a third party reaching a service the org deliberately published — and
// their address is the entire audit question ("who reached our staging box, and
// when"). Every reverse proxy on earth keeps this log. It is still personal
// data, which is why retention and the per-org opt-out are not optional.
//
// WHAT IS *NOT* RECORDED: request lines, paths, headers, bodies, user agents,
// or anything else from inside the stream. This package counts CONNECTIONS and
// their outcome. Bodies and paths are what the daemon's own :7400 inspector is
// for — on the tunnel owner's machine, inside their trust boundary.
//
// UNIT. A row counts CONNECTIONS, not requests: HTTP keep-alive puts many
// requests on one TCP connection and the edge accepts once. The console must
// say "connections" for the same reason.
package access

import (
	"strings"
	"sync"
	"time"
)

// Outcome is what the edge did with a visitor connection. Low cardinality by
// construction — it is a dimension of the stored row, so a free-form string
// here would become an unbounded table.
type Outcome string

const (
	// Allowed: the connection reached the tunnel owner's machine.
	Allowed Outcome = "allowed"
	// DeniedIP: refused by the tunnel's IP allow/deny policy.
	DeniedIP Outcome = "denied_ip"
	// DeniedAuth: refused for missing/!valid credentials (basic auth, OAuth).
	DeniedAuth Outcome = "denied_auth"
	// DeniedRate: refused by the tunnel's connection-rate cap.
	DeniedRate Outcome = "denied_rate"
)

// Valid reports whether o is one of the four known outcomes. The store side
// re-checks: an unknown value would widen the table's key space.
func (o Outcome) Valid() bool {
	switch o {
	case Allowed, DeniedIP, DeniedAuth, DeniedRate:
		return true
	}
	return false
}

// OverflowIP is the visitor_ip of the bucket everything past the per-hour cap
// folds into. Empty rather than a sentinel like "other" so it can never be
// confused with a real address, and so a query for a specific IP never
// accidentally matches it.
const OverflowIP = ""

const (
	// MaxVisitorsPerTunnelHour caps how many DISTINCT addresses one tunnel gets
	// its own rows for in one hour. Past it, further new addresses are counted
	// in the overflow bucket.
	//
	// The cap is the difference between a bounded table and a table whose size
	// is chosen by whoever points a scanner at a published tunnel. 256 is
	// generous for the thing this answers ("who reached our staging box") and
	// small enough that a scraped public endpoint costs 256 rows an hour, not
	// 50,000.
	MaxVisitorsPerTunnelHour = 256

	// MaxRows is a whole-recorder backstop for the case the per-tunnel cap does
	// not bind — thousands of tunnels each with a handful of visitors. Past it,
	// every new key folds into its bucket's overflow row.
	MaxRows = 20000

	// maxIPLen is the longest address we keep verbatim. An IPv6 address with a
	// zone is 45-ish characters; anything longer did not come from a socket.
	maxIPLen = 64
)

// key is one stored row's identity. It is exactly the table's unique index, so
// a row cannot exist here that the store cannot hold.
type key struct {
	OrgID    int64
	TunnelID int64
	IP       string
	Outcome  Outcome
	Hour     int64 // start of the UTC hour, unix seconds
}

// bucket is the scope the per-hour visitor cap applies to.
type bucket struct {
	OrgID    int64
	TunnelID int64
	Hour     int64
}

// Row is one aggregated record, as published.
type Row struct {
	OrgID     int64  `json:"org_id"`
	TunnelID  int64  `json:"tunnel_id"`
	VisitorIP string `json:"visitor_ip"`
	Outcome   string `json:"outcome"`
	// Hour is the start of the UTC hour, unix seconds. UTC in storage; the
	// console buckets for the viewer's own timezone when it displays.
	Hour int64 `json:"hour"`
	// Conns is how many visitor connections landed in this bucket SINCE THE
	// LAST DRAIN. It is a delta, not a running total, which is what makes the
	// store side a plain upsert-add with no baseline problem — unlike the mesh
	// connection reports, which read cumulative WireGuard counters.
	Conns int64 `json:"conns"`
}

// Recorder accumulates rows in memory between flushes.
//
// Everything it holds is a delta since the last Drain, so a crash loses at most
// one flush interval and nothing double-counts on restart.
type Recorder struct {
	mu       sync.Mutex
	counts   map[key]int64
	visitors map[bucket]map[string]struct{}
	// overflowed counts buckets that hit a cap, for the log line. Cleared with
	// the rest on Drain.
	overflowed int
}

// New returns an empty Recorder. A nil *Recorder is usable and does nothing,
// so a deployment with access records switched off needs no nil checks at the
// call sites.
func New() *Recorder {
	return &Recorder{
		counts:   make(map[key]int64),
		visitors: make(map[bucket]map[string]struct{}),
	}
}

// Note records one visitor connection. Safe on a nil receiver.
//
// An unattributed proxy (tunnelID 0 — a standalone proxy, or one whose row was
// never claimed) is DROPPED rather than bucketed at 0. The usage reporter keeps
// a tunnel_id=0 bucket because org bytes still have to be billed; an access
// record that cannot name the tunnel it belongs to answers nobody's question
// and would be the largest row in the table on a busy standalone edge.
func (r *Recorder) Note(orgID, tunnelID int64, ip string, o Outcome, now time.Time) {
	if r == nil || orgID <= 0 || tunnelID <= 0 || !o.Valid() {
		return
	}
	ip = normalizeIP(ip)
	hour := now.UTC().Truncate(time.Hour).Unix()
	b := bucket{OrgID: orgID, TunnelID: tunnelID, Hour: hour}

	r.mu.Lock()
	defer r.mu.Unlock()

	seen, ok := r.visitors[b]
	if !ok {
		seen = make(map[string]struct{})
		r.visitors[b] = seen
	}
	// An address already being counted this hour keeps its own row even once
	// the cap is reached — the cap limits how many DISTINCT addresses get named,
	// not how much a named one may do. Folding a known visitor into overflow
	// mid-hour would make its count silently wrong.
	if _, known := seen[ip]; !known && ip != OverflowIP {
		if len(seen) >= MaxVisitorsPerTunnelHour || len(r.counts) >= MaxRows {
			ip = OverflowIP
			r.overflowed++
		} else {
			seen[ip] = struct{}{}
		}
	}
	r.counts[key{OrgID: orgID, TunnelID: tunnelID, IP: ip, Outcome: o, Hour: hour}]++
}

// NoteAccess implements accesslog.Sink — the seam the visitor-facing listeners
// call through, which speaks plain strings so the open tree carries no
// dependency on this package.
//
// The outcome is re-typed and re-validated here rather than trusted: Note drops
// anything that is not one of the four known values, so a typo on the listener
// side loses that record instead of inventing a fifth dimension value in the
// stored table.
func (r *Recorder) NoteAccess(orgID, tunnelID int64, visitorIP, outcome string, at time.Time) {
	r.Note(orgID, tunnelID, visitorIP, Outcome(outcome), at)
}

// Drain returns everything accumulated and resets, along with how many
// connections were folded into an overflow bucket in that interval.
//
// The overflow count comes back HERE rather than from a separate getter
// because draining is the moment the interval ends: a getter would have to be
// called before Drain to mean anything, and a caller that got the order wrong
// would report zero forever without anything looking broken.
//
// Rows come back in no particular order; the store keys on the tuple, not on
// arrival.
func (r *Recorder) Drain() ([]Row, int) {
	if r == nil {
		return nil, 0
	}
	r.mu.Lock()
	counts := r.counts
	r.counts = make(map[key]int64)
	r.visitors = make(map[bucket]map[string]struct{})
	overflowed := r.overflowed
	r.overflowed = 0
	r.mu.Unlock()

	if len(counts) == 0 {
		return nil, overflowed
	}
	out := make([]Row, 0, len(counts))
	for k, n := range counts {
		out = append(out, Row{
			OrgID:     k.OrgID,
			TunnelID:  k.TunnelID,
			VisitorIP: k.IP,
			Outcome:   string(k.Outcome),
			Hour:      k.Hour,
			Conns:     n,
		})
	}
	return out, overflowed
}

// normalizeIP trims an address to something a column can hold. An address that
// arrives empty or absurd becomes the overflow bucket rather than a row keyed
// on garbage: the row still counts the connection, it just does not claim to
// know where it came from.
func normalizeIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" || len(ip) > maxIPLen {
		return OverflowIP
	}
	return ip
}
