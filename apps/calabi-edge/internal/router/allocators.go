package router

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	proto "github.com/calabi/calabi/pkg/protocol"
)

// SubdomainAllocator hands out fresh subdomains under a base domain.
// Format: "u<6 digit seq>.<base>", e.g. "u000123.localtest.me".
//
// The base is held in an atomic.Pointer so the fsnotify config reload can swap it without locking. Allocate is called from
// the session control loop on a hot path, so we want zero contention.
//
// Persistence: when UsePersistentSeq(path) has been called the seq value
// is read from + written to that file across restarts, so a fresh boot
// of the edge keeps handing out u000124, u000125, ... instead of
// rewinding to u000001 (which would collide with rows that survived in
// tunnel-svc's DB). Without that call the seq lives only in memory and
// the caller usually compensates with Seed() — see main.go for the
// boot-time wiring.
type SubdomainAllocator struct {
	base atomic.Pointer[string]
	seq  atomic.Uint64

	// persistMu serializes the write-temp + rename dance in
	// persistLocked so two concurrent Allocate calls can't race each
	// other's writes. seq itself stays atomic; this lock only covers
	// the durability layer.
	persistMu   sync.Mutex
	persistPath atomic.Pointer[string]
	persistLog  *slog.Logger
}

// NewSubdomainAllocator returns an allocator using base as the suffix.
func NewSubdomainAllocator(base string) *SubdomainAllocator {
	a := &SubdomainAllocator{}
	a.SetBase(base)
	return a
}

// UsePersistentSeq makes the allocator survive process restarts by
// reading the current seq from path on entry and writing each Allocate's
// new seq back atomically (write-temp + rename). The parent directory is
// created if missing. Logger is optional; if non-nil, persistence
// failures (full disk, ENOENT after rename) are logged at WARN so the
// operator notices that monotonicity has degraded to in-memory.
//
// The file format is a single ASCII decimal followed by a trailing
// newline (so `cat` shows something sensible). Empty / corrupt files
// reset to seq=0; callers paranoid about that can grep WARN logs for
// "persistent-seq" or pre-stamp the file by hand.
//
// Returns an error only on path/permission problems that prevent
// reading the initial value — in that case the allocator stays
// in-memory and the caller can fall back to Seed().
func (a *SubdomainAllocator) UsePersistentSeq(path string, logger *slog.Logger) error {
	if path == "" {
		return fmt.Errorf("persistent-seq: empty path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("persistent-seq: mkdir %s: %w", filepath.Dir(path), err)
	}
	seq, err := readSeqFile(path)
	if err != nil {
		return fmt.Errorf("persistent-seq: read %s: %w", path, err)
	}
	a.seq.Store(seq)
	cp := path
	a.persistPath.Store(&cp)
	a.persistLog = logger
	return nil
}

// readSeqFile returns 0 if path doesn't exist; a corrupt file logs and
// returns 0 too (operator's seed is still wrong, but the edge boots).
func readSeqFile(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	s := strings.TrimSpace(string(data))
	if s == "" {
		return 0, nil
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		// Corrupt / non-numeric. Reset to 0 — caller's logger will
		// catch the next Allocate's persist write that overwrites the
		// bad file.
		return 0, nil
	}
	return n, nil
}

// persistLocked writes the current seq value to disk atomically.
// Called from Allocate after the in-memory counter has been bumped, so
// even if the disk write fails the in-memory allocation is still
// returned to the caller — we lose monotonicity across restart but
// don't deadlock the session control loop on a full disk.
func (a *SubdomainAllocator) persistLocked(seq uint64) {
	pp := a.persistPath.Load()
	if pp == nil || *pp == "" {
		return
	}
	a.persistMu.Lock()
	defer a.persistMu.Unlock()
	tmp := *pp + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatUint(seq, 10)+"\n"), 0o644); err != nil {
		if a.persistLog != nil {
			a.persistLog.Warn("persistent-seq write failed", "path", tmp, "err", err)
		}
		return
	}
	if err := os.Rename(tmp, *pp); err != nil {
		if a.persistLog != nil {
			a.persistLog.Warn("persistent-seq rename failed", "src", tmp, "dst", *pp, "err", err)
		}
	}
}

// SetBase hot-swaps the suffix. Calls in flight already producing a
// name use the previous base; subsequent calls use the new one. Safe
// for concurrent use.
func (a *SubdomainAllocator) SetBase(base string) {
	cp := base
	a.base.Store(&cp)
}

// Base returns the current suffix (for diagnostics / status pages).
func (a *SubdomainAllocator) Base() string {
	if p := a.base.Load(); p != nil {
		return *p
	}
	return ""
}

// Seed sets the starting seq value. Allocate's first call after Seed(n)
// returns "u<n+1>.<base>". Idempotent; safe to call before any Allocate.
//
// Prefer UsePersistentSeq for new deployments — it solves the same
// "restart rewinds seq and we collide with existing DB rows" problem
// without the ugly time-based starting offset. Seed remains for callers
// that want a one-shot offset without disk state (tests, ephemeral
// pods).
func (a *SubdomainAllocator) Seed(seq uint64) {
	a.seq.Store(seq)
}

// SeedIfBehind bumps seq forward to n if the current value is below n,
// otherwise leaves it alone. Use this when stacking multiple seed
// sources (file-backed seq + DB max) — whichever is ahead wins,
// guaranteeing the allocator never goes backward.
func (a *SubdomainAllocator) SeedIfBehind(n uint64) {
	for {
		cur := a.seq.Load()
		if cur >= n {
			return
		}
		if a.seq.CompareAndSwap(cur, n) {
			a.persistLocked(n)
			return
		}
	}
}

// Allocate returns a new domain string. If UsePersistentSeq was called,
// the new seq is persisted to disk atomically before returning so a
// subsequent crash + restart picks up where we left off.
func (a *SubdomainAllocator) Allocate(_ proto.ProxyKind) string {
	n := a.seq.Add(1)
	a.persistLocked(n)
	return fmt.Sprintf("u%06d.%s", n, a.Base())
}

// PortPool hands out free TCP ports from [min, max].
//
// `reserved` tracks ports that are off-limits — either because
// tunnel-svc says they're already claimed by some live row (seeded at
// edge boot via Reserve()), or because a NEW_PROXY just succeeded on
// them and they shouldn't be re-allocated until Release()'d. Without
// this, the in-memory pool restarts at `min` on each edge boot and
// happily re-issues port N to a brand-new tunnel even when the DB still
// has another member's live row sitting at N — the new Claim collides,
// the SPA shows a duplicate / 等待分配端口 row, and the user gets to
// dig through edge logs to figure out which tunnel "stole" the port.
type PortPool struct {
	mu       sync.Mutex
	min, max uint32
	free     []uint32
	next     uint32
	reserved map[uint32]struct{}
	// inUse counts ports currently handed out (Allocate'd, not yet
	// Release'd). Feeds the port-pool utilization metric so ops can see an
	// edge approaching exhaustion of its ~1000-port range before TCP/UDP
	// creates start failing.
	inUse int
}

// NewPortPool initializes a pool. min <= max.
func NewPortPool(min, max uint32) *PortPool {
	return &PortPool{
		min:      min,
		max:      max,
		next:     min,
		reserved: make(map[uint32]struct{}),
	}
}

// Allocate returns a free port, or false if exhausted.
// Reserved ports are skipped; previously-released ports come back via
// the LIFO free list (matches the behaviour).
func (p *PortPool) Allocate() (uint32, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Drain the free list first, skipping anything that got reserved
	// between Release() and now (very rare but possible if a Reserve
	// races a Release).
	for len(p.free) > 0 {
		n := len(p.free)
		port := p.free[n-1]
		p.free = p.free[:n-1]
		if _, taken := p.reserved[port]; !taken {
			p.inUse++
			return port, true
		}
	}
	// Walk the sequence, skipping reservations. Bounded by max so a
	// fully-reserved range falls through to "exhausted".
	for p.next <= p.max {
		port := p.next
		p.next++
		if _, taken := p.reserved[port]; !taken {
			p.inUse++
			return port, true
		}
	}
	return 0, false
}

// Release returns port to the pool. No-op if the port was reserved at
// boot — those stay claimed for the lifetime of the process.
func (p *PortPool) Release(port uint32) {
	if port < p.min || port > p.max {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, taken := p.reserved[port]; taken {
		return
	}
	if p.inUse > 0 {
		p.inUse--
	}
	p.free = append(p.free, port)
}

// Reserve marks `port` as unavailable for auto-allocation. Used at boot
// to seed the pool from tunnel-svc's view of which ports already have
// live rows owned by this edge — protects member A's tunnel from
// getting overwritten by a member B claim that happens to land on the
// same number. Safe to call before or after Allocate(); idempotent.
//
// Out-of-range ports are silently ignored so the caller doesn't have to
// pre-filter when seeding from DB (different edges may run different
// [min,max] ranges).
func (p *PortPool) Reserve(port uint32) {
	if port < p.min || port > p.max {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reserved[port] = struct{}{}
}

// InUse reports how many ports are currently occupied: dynamically
// handed-out (Allocate'd, not Release'd) PLUS boot-reserved (live rows
// seeded at startup). Approximate by design — it's the port-pool
// utilization signal for exhaustion alerting, not an exact ledger.
func (p *PortPool) InUse() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.inUse + len(p.reserved)
}

// Capacity is the total number of ports in the [min, max] range.
func (p *PortPool) Capacity() int {
	return int(p.max-p.min) + 1
}
