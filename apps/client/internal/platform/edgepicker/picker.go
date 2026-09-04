// Package edgepicker resolves which calabi-edge the daemon should dial.
//
// The lookup tier-list, in order, returns the FIRST match:
//
//  1. explicit CALABI_SERVER env (legacy single-edge override)
//  2. region preference (flag / env / creds.Config.EdgeRegion) →
//     bff-console GET /v1/edges?region=<r> → first healthy edge's PublicAddr
//  3. region preference with no healthy match → /v1/edges (any region) fallback
//  4. defaultServer compile-time constant
//
// change: tier 2 used to dial identity-svc gRPC directly. Now it
// goes through bff-console REST so identity-svc stays inside the cluster
// and the daemon only needs one outbound endpoint (the SLB-fronted
// bff-console URL).
//
// Tier 2 is the add — it lets the multi-edge wildcard-DNS deploy
// mode steer a daemon at the edge whose subdomain zone its tunnels were
// originally allocated under, so the per-edge zone-edge consistency
// check on tunnel-svc (see TunnelServer.checkZoneEdge) doesn't trigger.
//
// On any HTTP failure the picker falls back to tier 4 instead of
// crashing the daemon — the user can still bring the data plane up
// against a hard-coded edge if bff-console is unreachable.
package edgepicker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Input bundles the inputs Pick needs. None are required; an entirely
// empty Input degrades to "use DefaultAddr".
type Input struct {
	// ExplicitAddr is the highest-priority override (env CALABI_SERVER).
	// When set, every other field is ignored.
	ExplicitAddr string
	// Region is the daemon's preferred region. Empty = no preference;
	// Pick skips the /v1/edges call entirely.
	Region string
	// RestrictToRegion locks selection to Region: when set (and Region is
	// non-empty), Pick will NOT fall through to the any-region query if the
	// region has no healthy edge. This is the "disable cross-region auto-
	// switch" knob — same-region failover still works (the region query
	// load-balances across the region's healthy edges), but the picker will
	// never silently hop the daemon to a DIFFERENT region. When the locked
	// region is reachable-but-empty, Pick returns Result.RegionUnavailable
	// so the daemon can park + prompt the user to switch region manually
	// instead of dialing a wrong-region edge.
	RestrictToRegion bool
	// BFFConsoleURL is the HTTP base of bff-console (e.g.
	// "http://api.calabi.net" or "http://127.0.0.1:8002" in dev). Empty
	// disables tier 2 even when Region is set. Set from
	// envOr("CALABI_BFF_CONSOLE", defaultBFFConsole) at the call site.
	BFFConsoleURL string
	// AccessToken gates the /v1/edges call (bff-console requires
	// Authorization: Bearer <jwt>). Pass cfg.AccessToken from creds.
	// Empty = unauthenticated request; bff-console will 401 and the
	// picker degrades to tier 4.
	AccessToken string
	// OrgID is plumbed through for completeness but bff-console's
	// /v1/edges currently treats edges as global (no org scoping).
	OrgID int64
	// PreferPlatformEdge inverts the BYOI soft-affinity. Default (false): if
	// the candidate list contains an edge the caller org owns (a self-hosted
	// BYOI edge, tagged owned=true by bff-console), Pick narrows to those —
	// the org's tunnels default to its own edge. When true, Pick narrows to
	// PLATFORM edges instead (the customer paid for the plan, so they may
	// always run on the platform data plane). If the preferred class is empty
	// in a given query, Pick falls back to the full candidate set rather than
	// strand the daemon. Sourced from creds.PreferPlatformEdge.
	PreferPlatformEdge bool
	// DefaultAddr is the compile-time hard-coded fallback for tier 4
	// (e.g. "127.0.0.1:7443" in dev).
	DefaultAddr string
	// StickyEdgeNodeID is the edge_node_id the daemon used on its last
	// successful boot (from creds.LastEdgeNodeID). When non-zero, Pick
	// looks for this id in the /v1/edges healthy list first and dials
	// it regardless of active_clients ranking. If the id is missing or
	// unhealthy, Pick falls back to the normal load-balancing path AND
	// sets Result.Switched so daemon can warn the user that tunnels
	// bound to the old edge are temporarily unreachable.
	//
	// 0 = no preference; behaviour is the original load-balanced
	// selection.
	StickyEdgeNodeID int64
	// RefreshBearer, when non-nil, is invoked if a /v1/edges query comes
	// back 401 (the stored AccessToken expired). It should exchange the
	// refresh token for a fresh access token, persist it, and return the
	// new bearer ("" if it couldn't). Pick then retries the lookup once
	// with the returned token before falling back to DefaultAddr.
	//
	// Why this exists: on a cold daemon boot the stored access_token may
	// have expired while the daemon was down, and edgepicker runs BEFORE
	// any SPA / statusapi traffic could have lazily refreshed it. Without
	// this hook the first Pick 401s, falls back to DefaultAddr (localhost
	// in dev), and the user eats a full ~15s reconnect cycle before some
	// other code path refreshes the token and the next tick succeeds.
	//
	// nil = no refresh; behaviour is the original "401 → fall back".
	RefreshBearer func(ctx context.Context) string
}

// Result describes which edge Pick chose, plus the path it took. Daemon
// logs the path so users can debug "why am I connecting to the wrong
// edge".
type Result struct {
	Addr   string // dialed address
	Region string // the edge's region (empty when chosen via explicit/default)
	Reason string // human-readable explanation for the daemon log
	// EdgeNodeID is the identity-svc edge_node_id of the chosen edge.
	// 0 when the choice came from CALABI_SERVER or the compile-time
	// default (no /v1/edges round-trip to learn the id). Daemon
	// persists this back to creds.LastEdgeNodeID so the next boot can
	// stick to the same edge.
	EdgeNodeID int64
	// Switched is true when Input.StickyEdgeNodeID was non-zero AND the
	// final pick is a DIFFERENT edge — i.e. the previous edge dropped
	// out of the healthy set or was rejected by region filter. Daemon
	// reads this to raise an SPA banner ("tunnels bound to old edge
	// are temporarily unreachable").
	//
	// False when StickyEdgeNodeID was 0 (first run, nothing to compare),
	// when the sticky id matched, OR when the pick fell to tier 1/4
	// (no /v1/edges data, can't decide).
	Switched bool
	// RegionUnavailable is true when Input.RestrictToRegion was set, the
	// region query reached bff-console, but it returned no healthy edge in
	// the locked region. Addr is empty in this case — the daemon must NOT
	// dial; it parks the reconnect loop and surfaces "服务器不可用，可手动
	// 切换地域" so the user picks another region by hand (cross-region auto-
	// switch is deliberately disabled). Distinct from "bff-console
	// unreachable", which falls through to DefaultAddr as before.
	RegionUnavailable bool
	// PreviousEdgeNodeID echoes Input.StickyEdgeNodeID only when
	// Switched is true, so the daemon can show "switched from edge #X
	// to edge #Y" without re-reading creds.
	PreviousEdgeNodeID int64
}

// edgeJSON mirrors the JSON shape bff-console returns from /v1/edges.
// Field names match the API (identity.proto EdgeNode), no renames.
type edgeJSON struct {
	EdgeNodeID    int64  `json:"edge_node_id"`
	NodeLabel     string `json:"node_label"`
	Region        string `json:"region"`
	PublicAddr    string `json:"public_addr"`
	Healthy       bool   `json:"healthy"`
	ActiveClients int32  `json:"active_clients"`
	// Owned is true when bff-console tagged this edge as one of the caller
	// org's self-hosted BYOI edges. Drives the soft-affinity narrowing.
	Owned bool `json:"owned"`
}

type listEdgesResponse struct {
	Items []edgeJSON `json:"items"`
}

// narrowByOwnership applies the BYOI soft-affinity: by default it keeps only
// the org's OWN edges (owned=true) when any are present; when preferPlatform
// is set it keeps only PLATFORM edges (owned=false) when any are present. If
// the preferred class is absent it returns the input unchanged — a daemon must
// never be stranded just because its preferred class has no healthy edge right
// now (e.g. own edge offline → fall back to platform, and vice-versa).
func narrowByOwnership(logger *slog.Logger, cands []edgeJSON, preferPlatform bool) []edgeJSON {
	var owned, platform []edgeJSON
	for _, e := range cands {
		if e.Owned {
			owned = append(owned, e)
		} else {
			platform = append(platform, e)
		}
	}
	if preferPlatform {
		if len(platform) > 0 {
			if len(owned) > 0 {
				logger.Info("edgepicker: prefer-platform — using platform edge over own BYOI edge")
			}
			return platform
		}
		return cands // only own edges available — don't strand the daemon
	}
	if len(owned) > 0 {
		logger.Info("edgepicker: BYOI affinity — defaulting to org's own edge", "owned_count", len(owned))
		return owned
	}
	return cands
}

// narrowToRegion keeps only the candidates actually IN the requested region —
// unless none of them are, in which case the out-of-region ones stand. That
// exception is the BYOI affinity case: the region the daemon is anchored to
// holds none of the org's own edges, and landing on its own edge elsewhere is
// what the caller wanted. No-op for an any-region query.
func narrowToRegion(logger *slog.Logger, cands []edgeJSON, region string) []edgeJSON {
	if region == "" {
		return cands
	}
	inRegion := make([]edgeJSON, 0, len(cands))
	for _, e := range cands {
		if e.Region == region {
			inRegion = append(inRegion, e)
		}
	}
	if len(inRegion) == 0 || len(inRegion) == len(cands) {
		return cands
	}
	if logger != nil {
		logger.Info("edgepicker: dropping out-of-region edges the region query returned anyway",
			"region", region, "kept", len(inRegion), "dropped", len(cands)-len(inRegion))
	}
	return inRegion
}

// Pick resolves the dial address. Never returns error — the worst-case
// path is "fall back to DefaultAddr and log the failure". Caller passes
// a short ctx so a degraded bff-console doesn't pin daemon boot.
func Pick(ctx context.Context, logger *slog.Logger, in Input) Result {
	// Tier 1: explicit override always wins.
	if in.ExplicitAddr != "" {
		r := Result{
			Addr:   in.ExplicitAddr,
			Reason: "CALABI_SERVER env override",
		}
		// Best-effort: still resolve WHICH edge this is by matching the explicit
		// address against the /v1/edges directory. Without this the override
		// leaves EdgeNodeID=0, which silently breaks everything keyed on the
		// edge identity — most visibly the BYOI custom-domain gate (the wizard's
		// onOwnEdge check compares snap.edge_node_id to an owned /v1/edges row),
		// but also the served-by-edge labels, the region chip, and sticky-edge
		// persistence. A miss leaves id 0 — exactly the old behavior — so this
		// can only ever improve things. Common case: a BYOI user pins their own
		// edge via CALABI_SERVER and then couldn't pick their verified domain.
		if in.BFFConsoleURL != "" {
			if e, ok := resolveExplicitEdgeID(ctx, logger, in, in.ExplicitAddr); ok {
				r.EdgeNodeID = e.EdgeNodeID
				r.Region = e.Region
				r.Reason = fmt.Sprintf("CALABI_SERVER env override → edge #%d (region %q)",
					e.EdgeNodeID, e.Region)
			}
		}
		return r
	}

	// Tier 2/3: ask bff-console. Even with no region preference we still
	// call GET /v1/edges (no region filter) — the typical CN-only deploy
	// has a single region and daemon users shouldn't need to pass
	// --edge-region to get a working edge dial address.
	if in.BFFConsoleURL != "" {
		r, ok := pickByListEdges(ctx, logger, in)
		if ok {
			return r
		}
		// Region-locked + the region had no healthy edge: do NOT fall to
		// the compile-time default (that could be a wrong-region edge).
		// Hand the RegionUnavailable signal back so the daemon parks.
		if r.RegionUnavailable {
			return r
		}
	}

	// Tier 4: default. We get here when no bff-console URL or all
	// region queries failed.
	return Result{
		Addr:   in.DefaultAddr,
		Reason: "compile-time default (no bff-console URL or /v1/edges unreachable)",
	}
}

// pickByListEdges issues GET /v1/edges?region=<r> and, on miss, retries
// without the region filter. When Region is empty we go straight to the
// no-filter query. Returns ok=false when all queries fail or yield no
// healthy candidate.
//
// Sticky preference: when Input.StickyEdgeNodeID is non-zero we look for
// it in the candidate list first and pick it regardless of
// active_clients ranking. A miss falls through to load-balanced
// selection AND raises Result.Switched so daemon can warn the user.
func pickByListEdges(ctx context.Context, logger *slog.Logger, in Input) (Result, bool) {
	client := &http.Client{Timeout: 5 * time.Second}

	res, ok, authFailed, regionUnavail := attemptListEdges(ctx, logger, client, in)
	if ok {
		return res, true
	}

	// Cold-boot recovery: the only failure worth a token refresh is 401.
	// edgepicker runs before any SPA/statusapi traffic, so on a daemon
	// boot with an expired access_token nothing else has refreshed it yet.
	// Refresh once inline + retry so we connect straight to the real edge
	// instead of falling back to DefaultAddr and burning a reconnect cycle.
	if authFailed && in.RefreshBearer != nil {
		if nt := in.RefreshBearer(ctx); nt != "" && nt != in.AccessToken {
			in.AccessToken = nt
			logger.Info("edgepicker: bearer refreshed after 401; retrying /v1/edges")
			if res2, ok2, _, ru2 := attemptListEdges(ctx, logger, client, in); ok2 {
				return res2, true
			} else {
				regionUnavail = ru2
			}
		}
	}

	// Region-locked + the region is reachable-but-empty: signal
	// RegionUnavailable so the daemon parks instead of hopping regions or
	// dialing the compile-time default. Cross-region auto-switch disabled.
	if regionUnavail {
		logger.Warn("edgepicker: region locked + no healthy edge — NOT auto-switching region (manual switch required)",
			"region", in.Region)
		return Result{
			Region:            in.Region,
			RegionUnavailable: true,
			Reason:            fmt.Sprintf("region %q has no healthy edge; cross-region auto-switch disabled", in.Region),
		}, false
	}

	logger.Warn("edgepicker: /v1/edges returned no healthy edges; falling back to default",
		"preferred_region", in.Region)
	return Result{}, false
}

// attemptListEdges runs the region-then-any query pair once with the
// bearer currently in `in`. Returns (result, ok, authFailed, regionUnavailable):
//   - authFailed is true when a query came back 401, so the caller can decide
//     whether a token refresh + retry is worthwhile.
//   - regionUnavailable is true when RestrictToRegion was set, the region
//     query reached bff-console, but it had no healthy edge — the daemon
//     should park (cross-region auto-switch is disabled) rather than fall
//     through to the any-region query or the compile-time default.
func attemptListEdges(ctx context.Context, logger *slog.Logger, client *http.Client, in Input) (Result, bool, bool, bool) {
	authFailed := false

	// Region preference set → try it first.
	if in.Region != "" {
		chosen, ok, unauth, reached := queryListEdges(ctx, logger, client, in, in.Region)
		if ok {
			return buildResult(in, chosen,
				fmt.Sprintf("bff-console GET /v1/edges?region=%q", in.Region)), true, false, false
		}
		authFailed = authFailed || unauth
		if in.RestrictToRegion {
			// Cross-region auto-switch disabled — do NOT try other regions.
			// reached=true ⇒ the region genuinely has no healthy edge right
			// now → flag RegionUnavailable so the daemon parks + prompts a
			// manual switch. reached=false ⇒ couldn't reach bff-console at
			// all → leave it unset so Pick falls back to DefaultAddr (the
			// control-plane-down best-effort path, unchanged).
			return Result{Region: in.Region}, false, authFailed, reached
		}
		logger.Info("edgepicker: no healthy edge in preferred region; trying any region",
			"region", in.Region)
	}

	// No region preference OR preferred region empty → query all.
	chosen, ok, unauth, _ := queryListEdges(ctx, logger, client, in, "")
	if ok {
		reason := "bff-console GET /v1/edges (any region)"
		if in.Region != "" {
			reason = fmt.Sprintf("bff-console GET /v1/edges (any region) — preferred %q was empty", in.Region)
		}
		return buildResult(in, chosen, reason), true, false, false
	}
	authFailed = authFailed || unauth
	return Result{}, false, authFailed, false
}

// buildResult assembles the Result and flags Switched when sticky was
// requested but the final pick is a different edge. Kept separate so
// every /v1/edges success path runs the same comparison.
func buildResult(in Input, chosen edgeJSON, reasonPrefix string) Result {
	r := Result{
		Addr:       chosen.PublicAddr,
		Region:     chosen.Region,
		EdgeNodeID: chosen.EdgeNodeID,
	}
	if in.StickyEdgeNodeID != 0 && chosen.EdgeNodeID != in.StickyEdgeNodeID {
		r.Switched = true
		r.PreviousEdgeNodeID = in.StickyEdgeNodeID
		r.Reason = fmt.Sprintf("%s → edge #%d (sticky #%d unavailable, load-balanced fallback)",
			reasonPrefix, chosen.EdgeNodeID, in.StickyEdgeNodeID)
	} else if in.StickyEdgeNodeID != 0 && chosen.EdgeNodeID == in.StickyEdgeNodeID {
		r.Reason = fmt.Sprintf("%s → edge #%d (sticky hit)",
			reasonPrefix, chosen.EdgeNodeID)
	} else {
		r.Reason = fmt.Sprintf("%s → edge #%d (first healthy)",
			reasonPrefix, chosen.EdgeNodeID)
	}
	return r
}

// queryListEdges issues one HTTP GET /v1/edges?region=<region> and
// returns the chosen edge. Return is (edge, ok, unauthorized, reached):
//   - ok=false on HTTP error, non-200, or empty/no-healthy result.
//   - unauthorized=true ONLY when the response was 401 — the caller uses
//     it to decide whether refreshing the bearer + retrying is worth it.
//   - reached=true when bff-console answered 200 and the body decoded,
//     regardless of whether a healthy candidate existed. The region-lock
//     path uses it to tell "region is up but empty" (→ RegionUnavailable)
//     from "couldn't reach bff-console" (→ fall back to DefaultAddr).
//
// Selection precedence within the candidate list:
//  1. If Input.StickyEdgeNodeID is non-zero AND that id is in the
//     healthy set → pick it (regardless of active_clients).
//  2. Otherwise → lowest active_clients, ties broken by edge_node_id.
func queryListEdges(parent context.Context, logger *slog.Logger, client *http.Client, in Input, region string) (edgeJSON, bool, bool, bool) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()

	base := strings.TrimRight(in.BFFConsoleURL, "/")
	u := base + "/v1/edges"
	if region != "" {
		u += "?region=" + url.QueryEscape(region)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		logger.Warn("edgepicker: build request failed", "url", u, "err", err)
		return edgeJSON{}, false, false, false
	}
	if in.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+in.AccessToken)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		logger.Warn("edgepicker: GET /v1/edges failed",
			"url", u, "err", err)
		return edgeJSON{}, false, false, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		logger.Warn("edgepicker: /v1/edges non-200",
			"url", u, "status", resp.StatusCode, "body", string(body))
		return edgeJSON{}, false, resp.StatusCode == http.StatusUnauthorized, false
	}

	var out listEdgesResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		logger.Warn("edgepicker: decode /v1/edges response failed", "err", err)
		return edgeJSON{}, false, false, false
	}
	// From here on bff-console answered cleanly — reached=true even when the
	// (region-filtered) list is empty or has no healthy edge.
	if len(out.Items) == 0 {
		return edgeJSON{}, false, false, true
	}

	candidates := make([]edgeJSON, 0, len(out.Items))
	for _, e := range out.Items {
		if !e.Healthy {
			continue
		}
		if e.PublicAddr == "" {
			continue
		}
		candidates = append(candidates, e)
	}
	if len(candidates) == 0 {
		return edgeJSON{}, false, false, true
	}

	// BYOI soft-affinity: narrow to the org's OWN edges by default (so a
	// BYOI org's tunnels — and its custom domains — land on its own edge),
	// or to PLATFORM edges when the user opted out (they paid for the plan).
	// Narrowing happens BEFORE sticky/load so both honour the chosen class.
	candidates = narrowByOwnership(logger, candidates, in.PreferPlatformEdge)

	// A region-scoped query is deliberately OVER-answered by bff-console: it adds
	// the org's own edges from every region so a daemon anchored where it owns
	// nothing still lands on its own edge. That superset must not be allowed to
	// override an EXPLICIT region choice — with two self-hosted edges the sticky
	// preference below would keep re-selecting the one the user had just asked to
	// leave, and switching regions became a one-way trip.
	//
	// AFTER the ownership narrowing, not before: running it first would drop the
	// out-of-region own edge while in-region platform edges survive, which is the
	// affinity case the superset exists for in the first place.
	candidates = narrowToRegion(logger, candidates, region)

	// Sticky-edge preference: if the last-used edge_node_id is in the
	// healthy set, use it. This is the fix — without it daemon
	// reboots could land on a different edge in the same region and
	// silently break the user's tunnel URLs (DNS is per-edge wildcard).
	if in.StickyEdgeNodeID != 0 {
		for _, e := range candidates {
			if e.EdgeNodeID == in.StickyEdgeNodeID {
				return e, true, false, true
			}
		}
	}

	// Fallback: lowest active_clients (ties by edge_node_id for stable
	// ordering across daemon binaries).
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].ActiveClients != candidates[j].ActiveClients {
			return candidates[i].ActiveClients < candidates[j].ActiveClients
		}
		return candidates[i].EdgeNodeID < candidates[j].EdgeNodeID
	})
	return candidates[0], true, false, true
}

// resolveExplicitEdgeID best-effort maps an explicit CALABI_SERVER dial address
// to its directory edge_node_id (+ region) by listing /v1/edges and matching on
// public_addr. Used only on the explicit-override path so that pinning an edge
// by address still yields a known edge identity. Pure best-effort: any failure
// (directory unreachable, non-200, no match) returns ok=false and the caller
// keeps EdgeNodeID=0 — never worse than before. Match priority: exact
// host:port, then host-only (the dialed control port may differ from the
// advertised public_addr port).
func resolveExplicitEdgeID(ctx context.Context, logger *slog.Logger, in Input, addr string) (edgeJSON, bool) {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	u := strings.TrimRight(in.BFFConsoleURL, "/") + "/v1/edges"
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, u, nil)
	if err != nil {
		return edgeJSON{}, false
	}
	if in.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+in.AccessToken)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		logger.Info("edgepicker: resolve explicit edge id — GET /v1/edges failed", "err", err)
		return edgeJSON{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return edgeJSON{}, false
	}
	var out listEdgesResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return edgeJSON{}, false
	}
	wantHost, _ := hostPort(addr)
	var hostMatch *edgeJSON
	for i := range out.Items {
		e := out.Items[i]
		if e.PublicAddr == "" {
			continue
		}
		if e.PublicAddr == addr { // exact host:port
			return e, true
		}
		if h, _ := hostPort(e.PublicAddr); h != "" && h == wantHost && hostMatch == nil {
			ee := e
			hostMatch = &ee
		}
	}
	if hostMatch != nil {
		return *hostMatch, true
	}
	logger.Info("edgepicker: CALABI_SERVER address not found in /v1/edges; edge id stays 0", "addr", addr)
	return edgeJSON{}, false
}

// hostPort splits "host:port" but tolerates a bare host (returns port ""). Empty
// in → ("", "").
func hostPort(addr string) (string, string) {
	if addr == "" {
		return "", ""
	}
	if h, p, err := net.SplitHostPort(addr); err == nil {
		return h, p
	}
	return addr, ""
}
