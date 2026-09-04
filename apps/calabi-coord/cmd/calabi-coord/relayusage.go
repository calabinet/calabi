package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
	meshproto "github.com/calabi/calabi/pkg/mesh-proto"
)

// Collecting relay usage (F2).
//
// The coordinator PULLS, from the platform's own relays only. A relay running on
// a user's VPS is never in this list, so its traffic never reaches the platform
// at all — self-hosted bandwidth is un-billable by construction rather than by
// policy. and
// the edge's relayreporter.go for the other half of the argument.
//
// The addresses live in their own section of the map file, NOT in core.DERPMap.
// That struct is converted to the netmap every node receives; an internal
// address that carries a credential has no business sharing a type with data
// that is broadcast to every client, where one reflexive line in a conversion
// function would publish it.

const (
	relayUsageTokenEnv    = "RELAY_USAGE_TOKEN"
	relayUsageIntervalEnv = "RELAY_USAGE_INTERVAL"
	// One minute, matching calabi-edge's usage reporter: the metering tables are
	// per-minute buckets, so a slower poll would produce a spiky series without
	// changing any total.
	defaultRelayUsageTick = time.Minute
)

// relayUsagePoller drains each platform relay's counters and hands the result to
// the coordinator for attribution.
type relayUsagePoller struct {
	coord    *core.Coordinator
	byRegion map[string]string // region code -> base URL
	token    string
	tick     time.Duration
	hc       *http.Client
	logger   *slog.Logger

	// pending holds usage that was collected but could not be recorded. Reading
	// the relay RESET its counters, so these bytes exist nowhere else — dropping
	// them on a transient sink failure would silently under-bill. Merged into the
	// next round and bounded by the number of nodes, not by how long the sink is
	// down.
	pending map[string]map[meshproto.NodeKey]core.RelayUsage
}

// newRelayUsagePoller returns nil when collection isn't configured — no token,
// or no relay published an address to collect from.
func newRelayUsagePoller(coord *core.Coordinator, byRegion map[string]string, logger *slog.Logger) *relayUsagePoller {
	token := env(relayUsageTokenEnv)
	if token == "" || len(byRegion) == 0 {
		logger.Info("coord: relay usage collection disabled",
			"has_token", token != "", "relays_with_address", len(byRegion))
		return nil
	}
	tick := defaultRelayUsageTick
	if raw := env(relayUsageIntervalEnv); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			logger.Warn("coord: bad "+relayUsageIntervalEnv+"; using the default", "value", raw, "default", tick)
		} else {
			tick = d
		}
	}
	for region, base := range byRegion {
		if u, err := url.Parse(base); err == nil && u.Scheme != "https" {
			// The token and the traffic graph both cross this link in cleartext.
			// Tolerated for a private network; called out loudly because "it
			// worked" looks identical either way.
			logger.Warn("coord: collecting relay usage over plaintext; the token and the usage are exposed on this path",
				"region", region, "url", base)
		}
	}
	logger.Info("coord: relay usage collection enabled", "relays", len(byRegion), "interval", tick)
	return &relayUsagePoller{
		coord: coord, byRegion: byRegion, token: token, tick: tick,
		hc:      &http.Client{Timeout: 15 * time.Second},
		logger:  logger,
		pending: map[string]map[meshproto.NodeKey]core.RelayUsage{},
	}
}

// Run polls until ctx is done.
func (p *relayUsagePoller) Run(ctx context.Context) {
	t := time.NewTicker(p.tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.collect(ctx)
		}
	}
}

func (p *relayUsagePoller) collect(ctx context.Context) {
	for _, region := range sortedKeys(p.byRegion) {
		fetched, err := p.fetch(ctx, p.byRegion[region])
		if err != nil {
			// Nothing was drained, so nothing is lost; the next tick retries.
			p.logger.Warn("coord: relay usage fetch failed", "region", region, "err", err)
		}
		merged := p.merge(region, fetched)
		if len(merged) == 0 {
			continue
		}
		attributed, dropped, err := p.coord.RecordRelayUsage(ctx, region, merged)
		if err != nil {
			p.logger.Error("coord: relay usage not recorded; holding it for the next round",
				"region", region, "entries", len(merged), "err", err)
			continue // pending keeps it
		}
		delete(p.pending, region)
		p.logger.Debug("coord: relay usage recorded", "region", region, "attributed", attributed, "dropped", dropped)
	}
}

// fetch drains one relay. NOTE: a successful read has already reset that relay's
// counters, so from here on the caller owns these bytes.
func (p *relayUsagePoller) fetch(ctx context.Context, base string) ([]core.RelayUsage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/usage", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	resp, err := p.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("relay returned %s", resp.Status)
	}
	var body struct {
		Deltas []core.RelayUsage `json:"deltas"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return body.Deltas, nil
}

// merge folds a fresh read into whatever is still owed for that region and
// returns the whole outstanding total.
func (p *relayUsagePoller) merge(region string, fetched []core.RelayUsage) []core.RelayUsage {
	held := p.pending[region]
	if held == nil {
		held = map[meshproto.NodeKey]core.RelayUsage{}
	}
	for _, u := range fetched {
		cur := held[u.Key]
		cur.Key = u.Key
		cur.BytesIn += u.BytesIn
		cur.BytesOut += u.BytesOut
		held[u.Key] = cur
	}
	if len(held) == 0 {
		return nil
	}
	p.pending[region] = held
	out := make([]core.RelayUsage, 0, len(held))
	for _, u := range held {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key.String() < out[j].Key.String() })
	return out
}

// loadRelayUsageAddrs reads the map file's usage_collection section. Absent file
// or section = nothing to collect, which is the normal state until relays are
// configured with a usage token.
//
// Region codes are NOT validated against the map. A typo costs a mislabeled
// region on a usage record, nothing more: attribution runs off the node key the
// relay reported, so the bytes still land on the right org either way.
func loadRelayUsageAddrs(logger *slog.Logger) map[string]string {
	path := env("DERP_MAP_FILE")
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		logger.Warn("coord: cannot read the derp map file for usage collection", "path", path, "err", err)
		return nil
	}
	var f derpMapFile
	if err := json.Unmarshal(raw, &f); err != nil {
		logger.Warn("coord: cannot parse the derp map file for usage collection", "path", path, "err", err)
		return nil
	}
	out := map[string]string{}
	for region, base := range f.UsageCollection {
		base = strings.TrimSpace(base)
		if region == "" || base == "" {
			continue
		}
		u, err := url.Parse(base)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			logger.Warn("coord: ignoring usage_collection entry (want an http/https base URL)", "region", region, "value", base)
			continue
		}
		out[region] = base
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
