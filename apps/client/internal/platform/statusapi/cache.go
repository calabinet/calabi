package statusapi

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"
)

// responseCache is a tiny per-(URL, token-hash) memoizer for GET
// responses the SPA polls hot.
//
// Why we need it
// --------------
// The SPA hammers /v1/tunnels every 8s and /v1/usage/current every 30s.
// statusapi forwarded each of those straight to bff-console with no
// caching, which made every SPA refetch a real HTTP+DB round-trip. At
// 10k clients × 5% open-SPA rate × these poll cadences the bff was
// servicing ~575k HTTP req/min worth of essentially-the-same query.
//
// This cache is the daemon-side memoizer documented in We picked daemon-side TTL over
// end-to-end ETag because:
//
//   - No bff-console schema change required (ETag would mean teaching
//     every cacheable handler to emit a stable hash).
//   - The data we cache is short-lived per-user state — tunnels and
//     usage — so a 15-30s staleness window is invisible to the UI.
//   - Local mutations (POST /v1/tunnels) invalidate the relevant
//     cache families immediately, so the user never sees "I created a
//     tunnel and the list didn't update".
//   - Remote mutations (someone deletes a tunnel from the web console)
//     surface within one TTL — acceptable.
//
// Cache key
// ---------
// The cache is keyed by (path-with-query, sha256(bearer)[:8]) so:
//
//   - Two SPAs talking to different users (multi-tenant dev) don't
//     each other's data.
//   - Token rotation (logout/login as a different user) automatically
//     creates a new cache bucket; the old one ages out via TTL.
//
// We deliberately do NOT key by request body — only GET paths are
// cached, so there's no body to vary over.
//
// Invalidation
// ------------
// Two paths invalidate cache entries:
//
//  1. proxy() observes write verbs (POST/PUT/DELETE) and calls
//     invalidatePrefix("/v1/tunnels") to drop the tunnel list family.
//  2. handleAuthLogin / handleAuthLogout call invalidateAll() — token
//     change means everything we cached is no longer the right user.
//
// We never invalidate /v1/usage/* on a write; usage counters tick on
// the data plane, not the API, so a tunnel CRUD doesn't move them.
//
// Concurrency
// -----------
// One RWMutex protects the whole map. The map is small (a handful of
// entries per active user) and accesses are read-heavy, so a striped
// or sync.Map would be premature.
type responseCache struct {
	mu      sync.RWMutex
	entries map[string]cachedResponse
}

// cachedResponse is one snapshot held by responseCache.
type cachedResponse struct {
	body       []byte
	headers    http.Header
	statusCode int
	expiresAt  time.Time
}

// newResponseCache constructs an empty cache. Callers usually stash the
// pointer on Server.
func newResponseCache() *responseCache {
	return &responseCache{
		entries: make(map[string]cachedResponse, 16),
	}
}

// cacheKey produces the lookup string from a request. The second arg is
// the bearer token in plaintext; we hash + truncate before mixing it
// into the key so we never persist the raw token in the cache map.
func cacheKey(fullPath, bearer string) string {
	if bearer == "" {
		return "anon:" + fullPath
	}
	sum := sha256.Sum256([]byte(bearer))
	return hex.EncodeToString(sum[:4]) + ":" + fullPath
}

// get returns a still-fresh entry or false. Callers MUST treat the
// returned slices/maps as read-only.
func (c *responseCache) get(key string) (cachedResponse, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[key]
	if !ok {
		return cachedResponse{}, false
	}
	if time.Now().After(e.expiresAt) {
		return cachedResponse{}, false
	}
	return e, true
}

// put writes a fresh entry; existing entries with the same key are
// overwritten.
func (c *responseCache) put(key string, e cachedResponse) {
	c.mu.Lock()
	c.entries[key] = e
	c.mu.Unlock()
}

// invalidatePrefix drops every entry whose path-component begins with
// prefix. We use this for the "user wrote a tunnel — drop the list
// cache" path. Token-hash is part of the key so prefix matching has to
// look past the first ':' separator.
func (c *responseCache) invalidatePrefix(prefix string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.entries {
		// keys look like "abcd1234:/v1/tunnels?x=y" or "anon:/v1/tunnels"
		idx := strings.IndexByte(k, ':')
		if idx < 0 {
			continue
		}
		path := k[idx+1:]
		if strings.HasPrefix(path, prefix) {
			delete(c.entries, k)
		}
	}
}

// invalidateAll wipes the whole cache. Used on login/logout where the
// bearer token (and therefore the data identity) changes wholesale.
func (c *responseCache) invalidateAll() {
	c.mu.Lock()
	c.entries = make(map[string]cachedResponse, 16)
	c.mu.Unlock()
}

// ttlFor decides how long a given path is cacheable. Zero TTL = do not
// cache.
//
// The mapping is intentionally hard-coded — we cache only the endpoints
// the SPA polls hot, so the cost of a stale read is bounded and well
// understood. Adding a new entry is a one-line change.
//
// Why these specific TTLs:
//   - /v1/tunnels (8s SPA poll, T=15s): catches the 2nd poll tick;
//     mutation-invalidation handles freshness after user actions.
//   - /v1/usage/current (30s SPA poll, T=45s): bff-console aggregates
//     5min buckets, so 45s lag is invisible to humans.
//   - /v1/me (rarely polled, T=120s): user record is near-static.
//   - /v1/plans (rarely polled, T=300s): plan catalog changes weekly.
//   - /v1/clients (rarely polled, T=15s): device list churns when a
//     daemon (re-)registers — 15s lag mirrors tunnel list semantics.
//
// /v1/usage/history and /v1/usage/daily are NOT cached: they're called
// during UI navigation, not in a polling loop, and the response varies
// by query string in ways that bloat the cache.
func ttlFor(path string) time.Duration {
	// Strip query so the table compares on path family alone.
	base := path
	if i := strings.IndexByte(base, '?'); i >= 0 {
		base = base[:i]
	}
	switch {
	case base == "/v1/tunnels":
		return 15 * time.Second
	case base == "/v1/usage/current":
		return 45 * time.Second
	case base == "/v1/me", base == "/v1/account/me":
		return 120 * time.Second
	case base == "/v1/plans":
		return 5 * time.Minute
	case base == "/v1/clients":
		return 15 * time.Second
	case base == "/v1/edges":
		// The edge directory shifts only when ops deploy/drain a node;
		// 30s lag is invisible to the user and saves the daemon a round-
		// trip per SPA poll tick.
		return 30 * time.Second
	}
	return 0
}
