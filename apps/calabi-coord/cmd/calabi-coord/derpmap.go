package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"

	"log/slog"

	"github.com/calabi/calabi/apps/calabi-coord/internal/core"
)

// derpMapFile is the on-disk shape of CALABI_COORD_DERP_MAP_FILE — the REAL relay
// directory an operator supplies (MESH.4). It mirrors core.DERPMap with stable
// JSON names so the fleet's actual calabi-derp endpoints (host + DERP/STUN ports)
// are listed from config, no rebuild. home_region names the region a node
// defaults to until it reports its own; empty falls back to the first region.
type derpMapFile struct {
	HomeRegion string `json:"home_region"`
	// UsageCollection maps a region code to the base URL coord drains that
	// relay's byte counters from (F2). Deliberately a SEPARATE section from
	// regions: those are broadcast to every node, this one carries an internal
	// address reached with a credential. Absent = that relay isn't collected.
	UsageCollection map[string]string `json:"usage_collection"`
	Regions         []struct {
		Code  string `json:"code"`
		Nodes []struct {
			HostName string `json:"host_name"`
			DERPPort int    `json:"derp_port"`
			STUNPort int    `json:"stun_port"`
		} `json:"nodes"`
	} `json:"regions"`
}

// loadDERPMap builds the relay directory coord distributes to nodes, plus the
// default home region stamped on a node that hasn't reported its own (MESH.4,
// surfaced as the "relay home" column). Source priority:
//  1. CALABI_COORD_DERP_MAP_FILE — the real fleet map (JSON), for a multi-relay
//     deployment. Set-but-broken is a startup error, never a silent fallback.
//  2. CALABI_COORD_DERP_ADDR (host:port) — a single-region map for the common
//     one-relay deploy. Point it at the SAME public relay endpoint mesh clients
//     dial so the map can't drift from reality.
//  3. the built-in dev PLACEHOLDER, loudly warned — a local run gets a non-empty
//     map; production supplies one of the above.
//
// Default home = the file's home_region (or CALABI_COORD_DERP_HOME_REGION) when it
// names a region present in the map, else the first region's code. Shared by both
// editions (no build tag).
func loadDERPMap(logger *slog.Logger) (core.DERPMap, string, error) {
	envHome := env("DERP_HOME_REGION")
	if path := env("DERP_MAP_FILE"); path != "" {
		m, home, err := readDERPMapFile(path, envHome)
		if err != nil {
			return core.DERPMap{}, "", fmt.Errorf("CALABI_COORD_DERP_MAP_FILE %q: %w", path, err)
		}
		logger.Info("derp map loaded from file", "path", path, "regions", len(m.Regions), "home_relay", home)
		return m, home, nil
	}
	if addr := env("DERP_ADDR"); addr != "" {
		m, home, err := singleRegionMap(addr, envHome, env("DERP_STUN_PORT"))
		if err != nil {
			return core.DERPMap{}, "", fmt.Errorf("CALABI_COORD_DERP_ADDR %q: %w", addr, err)
		}
		logger.Info("derp map: single region from CALABI_COORD_DERP_ADDR", "addr", addr, "home_relay", home)
		return m, home, nil
	}
	logger.Warn("no CALABI_COORD_DERP_MAP_FILE / CALABI_COORD_DERP_ADDR; using built-in PLACEHOLDER derp map (dev only — set one in production)")
	m := placeholderDERPMap()
	return m, defaultHome("", envHome, m), nil
}

// singleRegionMap builds a one-region DERP map from the deployment's public relay
// address (host:port — the exact endpoint mesh clients dial), so the map and the
// clients' relay can't drift. Region code = CALABI_COORD_DERP_HOME_REGION (default
// "default"); STUN port from CALABI_COORD_DERP_STUN_PORT (0/unset = none until
// endpoint discovery lands in the hole-punching slice). The home is that one
// region. Pure (only parses its args) — unit-testable.
func singleRegionMap(addr, region, stunPortEnv string) (core.DERPMap, string, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return core.DERPMap{}, "", fmt.Errorf("want host:port: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 {
		return core.DERPMap{}, "", fmt.Errorf("bad port %q", portStr)
	}
	if host == "" {
		return core.DERPMap{}, "", fmt.Errorf("empty host")
	}
	if region == "" {
		region = "default"
	}
	stun := 0
	if stunPortEnv != "" {
		if v, err := strconv.Atoi(stunPortEnv); err == nil && v > 0 {
			stun = v
		}
	}
	m := core.DERPMap{Regions: []core.DERPRegion{{
		Code:  region,
		Nodes: []core.DERPNode{{HostName: host, DERPPort: port, STUNPort: stun}},
	}}}
	return m, region, nil
}

// readDERPMapFile parses the operator's map file into core types and resolves the
// default home region. Pure enough to unit-test (only touches the given path).
func readDERPMapFile(path, envHome string) (core.DERPMap, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return core.DERPMap{}, "", err
	}
	var f derpMapFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return core.DERPMap{}, "", fmt.Errorf("parse: %w", err)
	}
	var m core.DERPMap
	for _, r := range f.Regions {
		if r.Code == "" {
			return core.DERPMap{}, "", fmt.Errorf("a region has an empty code")
		}
		reg := core.DERPRegion{Code: r.Code}
		for _, n := range r.Nodes {
			if n.HostName == "" || n.DERPPort == 0 {
				return core.DERPMap{}, "", fmt.Errorf("region %q: each node needs host_name + derp_port", r.Code)
			}
			reg.Nodes = append(reg.Nodes, core.DERPNode{HostName: n.HostName, DERPPort: n.DERPPort, STUNPort: n.STUNPort})
		}
		m.Regions = append(m.Regions, reg)
	}
	if len(m.Regions) == 0 {
		return core.DERPMap{}, "", fmt.Errorf("no regions")
	}
	return m, defaultHome(f.HomeRegion, envHome, m), nil
}

// defaultHome picks the region a new node defaults to: the file's home_region, or
// CALABI_COORD_DERP_HOME_REGION, when it names a region present in the map; otherwise
// the first region's code (never a home no relay backs). Empty map → "".
func defaultHome(fileHome, envHome string, m core.DERPMap) string {
	for _, want := range []string{fileHome, envHome} {
		if want == "" {
			continue
		}
		for _, r := range m.Regions {
			if r.Code == want {
				return want
			}
		}
	}
	if len(m.Regions) > 0 {
		return m.Regions[0].Code
	}
	return ""
}

// placeholderDERPMap is the DEV-ONLY relay directory (fictional hosts) so a local
// coord hands nodes a non-empty map. Production supplies CALABI_COORD_DERP_MAP_FILE.
func placeholderDERPMap() core.DERPMap {
	return core.DERPMap{Regions: []core.DERPRegion{
		{Code: "lax", Nodes: []core.DERPNode{{HostName: "derp-lax.calabi.net", DERPPort: 443, STUNPort: 3478}}},
		{Code: "sgp", Nodes: []core.DERPNode{{HostName: "derp-sgp.calabi.net", DERPPort: 443, STUNPort: 3478}}},
		{Code: "tyo", Nodes: []core.DERPNode{{HostName: "derp-tyo.calabi.net", DERPPort: 443, STUNPort: 3478}}},
		{Code: "fra", Nodes: []core.DERPNode{{HostName: "derp-fra.calabi.net", DERPPort: 443, STUNPort: 3478}}},
	}}
}
