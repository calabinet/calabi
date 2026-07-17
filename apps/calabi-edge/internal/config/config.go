// Package config loads calabi-edge configuration from YAML or environment.
//
// Schema is intentionally minimal; control-plane integration
// will replace static YAML with config-svc subscriptions.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration for calabi-edge.
type Config struct {
	NodeID string `yaml:"node_id"`
	Region string `yaml:"region"`
	// EdgeClass buckets this node into the plan-tier routing pool:
	//   "shared"    — default; every plan may dial it.
	//   "dedicated" — only plans entitled with features.dedicated_edge
	//                 (Business/Custom) are routed here by bff-console.
	// Empty is treated as "shared" by identity-svc, so leaving it unset
	// keeps legacy behaviour (a node serves all plans). Set it to
	// "dedicated" on the reserved pool you size for Business orgs.
	EdgeClass string `yaml:"edge_class"`

	// Mode selects whose security policy this edge trusts:
	//
	//   "platform" (default; empty) — managed / BYOI. Security policy is
	//       server-authoritative: it comes ONLY from the control plane's
	//       config_json (returned in the tunnel claim). Client-supplied policy
	//       in NEW_PROXY is IGNORED. The commercial per-plan gate + tenant
	//       isolation hold even though the edge binary is open-source.
	//
	//   "standalone" — self-hosted / open-source fork. The edge TRUSTS the
	//       per-proxy security policy the client supplies in NEW_PROXY
	//       (ProxyOptions.security_config_json) and enforces it directly — the
	//       operator owns the whole stack, so the client is the trust root.
	//
	// SAFETY: standalone is honoured ONLY when NO control plane is wired (a real
	// fork). A BYOI edge — which holds a control-plane-issued cert and dials the
	// control plane — keeps platform semantics EVEN IF mode=standalone is set,
	// so it can never self-grant paid features or weaken tenant isolation. The
	// guard lives in main.go (TrustsClientPolicy + the controlPlaneWired check).
	Mode string `yaml:"mode"`

	Control  ControlListener `yaml:"control"`
	HTTP     HTTPListener    `yaml:"http"`
	HTTPS    HTTPSListener   `yaml:"https"`
	SNI      SNIListener     `yaml:"sni"`
	Admin    AdminListener   `yaml:"admin"`
	Identity IdentityClient  `yaml:"identity"`
	Tunnel   TunnelClient    `yaml:"tunnel"`
	Cert     CertClient      `yaml:"cert"`
	Config   ConfigClient    `yaml:"config_svc"`
	Quota    QuotaClient     `yaml:"quota"`
	Nats     NatsClient      `yaml:"nats"`
	State    StateConfig     `yaml:"state"`
	Presence PresenceConfig  `yaml:"presence"`
	Public   PublicConfig    `yaml:"public"`
	Mesh     MeshConfig      `yaml:"mesh"`

	// AcceptedTokens is the temporary auth list. replaces this with
	// identity-svc gRPC lookup.
	AcceptedTokens []TokenEntry `yaml:"accepted_tokens"`

	// MultiRegion chooses how the edge reaches the control plane.
	// Defaults to mode=cluster which preserves behaviour
	// (direct dials to identity-svc / tunnel-svc / cert-svc / etc.
	// inside the same K8s cluster, NATS subscribed directly).
	//
	// When mode=bff-edge the edge ignores the Identity/Tunnel/Cert/
	// Quota/Config Addr fields above and instead routes every RPC and
	// NATS subject through a single mTLS gRPC connection to bff-edge.
	MultiRegion MultiRegionConfig `yaml:"multi_region"`

	Log LogConfig `yaml:"log"`
}

// ControlListener configures the client-facing TLS listener used to carry
// yamux-multiplexed control + data streams.
type ControlListener struct {
	Addr    string `yaml:"addr"`     // e.g. ":7443"
	CertPEM string `yaml:"cert_pem"` // path; empty = generate self-signed
	KeyPEM  string `yaml:"key_pem"`
}

// HTTPListener configures the public HTTP entrypoint (port 80 in prod, 8080
// in dev). HTTPS+ACME.
type HTTPListener struct {
	Addr       string `yaml:"addr"`        // e.g. ":8080"
	BaseDomain string `yaml:"base_domain"` // e.g. "localtest.me"
}

// SNIListener configures the TLS-SNI passthrough entrypoint. Empty Addr
// disables the listener entirely (sane default in dev where most users
// only need HTTP / TCP). In prod typically `:8443` co-existing alongside
// the HTTPS terminator on `:443`.
type SNIListener struct {
	Addr string `yaml:"addr"`
}

// HTTPSListener configures the TLS-terminating HTTPS entrypoint. Empty
// Addr disables it (sane default in dev). In prod typically `:443` for
// edge-served HTTPS tunnels.
//
// Distinct from sni: HTTPS terminates TLS at the edge using a cert from
// cert-svc; SNI just byte-passthroughs the raw TLS to the client.
type HTTPSListener struct {
	Addr string `yaml:"addr"`
	// SelfSigned, when true, lets the HTTPS terminator fall back to a
	// self-signed wildcard for HTTP.BaseDomain when cert-svc (or the
	// bff-edge cert bridge) has no cert for the requested SNI. DEV ONLY —
	// it makes HTTPS work in the multi-edge / bff-edge dev stack without
	// provisioning a real cert. NEVER set this in prod: there cert-svc is
	// the sole source of truth and a missing cert must fail the handshake,
	// not silently serve an untrusted self-signed cert.
	SelfSigned bool `yaml:"self_signed"`
}

// CertClient configures the cert-svc subscription. Empty Addr means
// "no HTTPS support" — the HTTPS listener will refuse to start because
// it has no GetCertificate source.
type CertClient struct {
	Addr           string `yaml:"addr"`            // e.g. "127.0.0.1:7005"
	OrgID          int64  `yaml:"org_id"`          // 0 = all orgs
	RefreshSeconds int    `yaml:"refresh_seconds"` // 0 = certclient default (30s)
}

// AdminListener configures the operational HTTP surface (/healthz, /readyz,
// /metrics). Should bind to a private interface in prod; never serve tenant
// traffic on this socket.
type AdminListener struct {
	Addr string `yaml:"addr"` // e.g. ":9101"
}

// IdentityClient configures the identity-svc gRPC client. Empty Addr means
// "fall back to the static accepted_tokens table".
type IdentityClient struct {
	Addr string `yaml:"addr"` // e.g. "127.0.0.1:7001"
}

// TunnelClient configures the tunnel-svc gRPC client. Empty Addr means
// "tunnels live in edge memory only".
type TunnelClient struct {
	Addr       string `yaml:"addr"`         // e.g. "127.0.0.1:7003"
	EdgeNodeID int64  `yaml:"edge_node_id"` // numeric edge id, 0 = derive from hash(node_id)
}

// QuotaClient configures the quota-svc lookup used by the per-session
// bandwidth limiter. Empty Addr means "no quota lookup;
// sessions stay unlimited" — sane default for dev / standalone edge.
type QuotaClient struct {
	Addr string `yaml:"addr"` // e.g. "127.0.0.1:7004"
}

// ConfigClient configures the config-svc gRPC client (NOT NATS — the
// edge subscribes via a server-streaming RPC, not directly to NATS).
// Empty Addr means "no live config push; route table is whatever this
// edge has built up from in-flight RegisterTunnel calls".
type ConfigClient struct {
	Addr    string `yaml:"addr"`    // e.g. "127.0.0.1:7005"
	Subject string `yaml:"subject"` // reserved for future use
	Stream  string `yaml:"stream"`  // reserved for future use
	Durable string `yaml:"durable"` // reserved for future use
}

// NatsClient configures the calabi-edge's direct NATS connection. This
// is separate from ConfigClient because the edge talks to config-svc
// over gRPC for route push, but goes directly to NATS for usage
// reports (calabi.usage.report publish + calabi.usage.deny.* sub).
// Empty URL means "no NATS; usage reporting silently no-ops".
type NatsClient struct {
	URL string `yaml:"url"` // e.g. "nats://127.0.0.1:4222"
}

// StateConfig controls where calabi-edge persists small bits of local
// state across restarts. Currently only the SubdomainAllocator seq
// lives here, but anything that needs to outlive a process restart
// (without going to a real DB) should land under this dir too.
//
// Empty Dir disables persistence — the allocator falls back to the
// boot-time time-based seed, which is ugly (u423156, u423157, ...) but
// avoids collisions with existing DB rows. Pointing this at a writable
// dir gets back monotonic u000001, u000002, ... naming.
type StateConfig struct {
	Dir string `yaml:"dir"` // e.g. "./state" (dev) / "/var/lib/calabi/edge" (prod)
}

// PublicConfig is what the edge advertises to clients via
// identity-svc.RegisterEdgeNode. Daemons doing ListEdges receive this
// addr verbatim; it MUST be reachable from the daemon's network
// (typically a public IP or DNS hostname mapping to one).
//
// Falls back to Control.Addr when unset — fine in single-host dev,
// wrong in any deploy where Control.Addr is a bind-only socket
// (e.g. ":7443" which routes nowhere from outside the container).
type PublicConfig struct {
	Addr string `yaml:"addr"` // e.g. "edge-cn-hz-1.calabi.io:7443"
}

// MeshConfig configures intra-region edge-mesh HA. When both
// fields are set this edge participates in same-region peer forwarding:
//   - it registers AdvertiseAddr as its `internal_addr` in the edge
//     directory (ListEdges), so peers know where to relay to;
//   - it listens on ForwardAddr for visitor connections relayed by a
//     peer edge that received traffic for a tunnel THIS edge owns.
//
// Empty (default) = single-edge region / mesh disabled: no peer
// listener, no internal_addr advertised, behaves exactly.
// Cross-region forwarding never happens — peers are only ever same-region
// edges (the owner registry + ListEdges are region-scoped).
type MeshConfig struct {
	// ForwardAddr is the VPC-internal bind addr for the peer-forward
	// listener, e.g. ":7090". MUST be reachable only inside the region's
	// VPC (security-group gated); never exposed to the public SLB.
	ForwardAddr string `yaml:"forward_addr"`
	// AdvertiseAddr is the VPC-internal host:port a peer dials to reach
	// ForwardAddr, e.g. "10.0.1.5:7090" or "edge-a.calabi.svc:7090".
	// Registered as internal_addr in the edge directory.
	AdvertiseAddr string `yaml:"advertise_addr"`
}

// MeshEnabled reports whether this edge participates in peer forwarding.
// Both bind + advertise addrs must be set; either blank = disabled.
func (c Config) MeshEnabled() bool {
	return c.Mesh.ForwardAddr != "" && c.Mesh.AdvertiseAddr != ""
}

// PresenceConfig controls how often the edge publishes its active
// (client_id, org_id) set to identity-svc.
//
// Tuning rationale:
//   - 10s (legacy default) — fastest UI feedback for "client is online"
//     but heaviest PG load at scale (3000 SQL QPS @ 10k clients before
//     X1 batching; 1000 QPS after).
//   - 15s (current default) — recommended for prod; identity-svc's
//     default freshness window is 35s = 2× heartbeat + slack.
//   - 20–30s — fine if UI staleness up to ~1 min is acceptable. Cuts
//     PG load proportionally.
//
// If IntervalSeconds is 0 the runtime defaults to 15s. Values below 5s
// are clamped to 5s to avoid hammering identity-svc during config typos.
type PresenceConfig struct {
	IntervalSeconds int `yaml:"interval_seconds"`
}

// PresenceInterval returns the heartbeat cadence with defaults + clamp
// applied. Centralised so the reporter and any other consumer agree.
func (p PresenceConfig) PresenceInterval() time.Duration {
	const def = 15 * time.Second
	const min = 5 * time.Second
	if p.IntervalSeconds <= 0 {
		return def
	}
	d := time.Duration(p.IntervalSeconds) * time.Second
	if d < min {
		return min
	}
	return d
}

// MultiRegionConfig selects the edge's control-plane access mode.
//
//	mode: cluster   (default) – direct gRPC + cluster NATS, in-cluster only.
//	mode: bff-edge            – single mTLS gRPC conn to bff-edge:443.
//
// Only used when Mode != "cluster". The mTLS client cert is signed by
// cert-svc's edge CA via `calabi-admin edge-cert issue`.
type MultiRegionConfig struct {
	// Mode is one of "cluster" or "bff-edge". Empty = "cluster".
	Mode string `yaml:"mode"`
	// BFFEdgeAddr is the public host:port (e.g. "bff-edge.calabi.net:443").
	BFFEdgeAddr string `yaml:"bff_edge_addr"`
	// ClientCert / ClientKey / CA are filesystem paths to PEM material.
	// ClientCert+Key are this edge's mTLS leaf; CA validates bff-edge's
	// server cert.
	ClientCert string `yaml:"client_cert"`
	ClientKey  string `yaml:"client_key"`
	CA         string `yaml:"ca"`
	// ServerName overrides the TLS SNI hostname when BFFEdgeAddr is an
	// IP literal (rare in prod; used for staging). Empty = host part of
	// BFFEdgeAddr.
	ServerName string `yaml:"server_name"`
}

// IsBFFEdge returns true when this edge should route every control-
// plane call through bff-edge instead of dialling individual svc
// ClusterIPs. Robust against blank yaml values.
func (m MultiRegionConfig) IsBFFEdge() bool {
	return m.Mode == "bff-edge"
}

// IsStandaloneMode reports whether this edge is configured as a self-hosted /
// open-source fork (top-level `mode: standalone`). Case- and whitespace-
// insensitive; any other value (including empty) means platform / managed.
func (c Config) IsStandaloneMode() bool {
	return strings.EqualFold(strings.TrimSpace(c.Mode), "standalone")
}

// TrustsClientPolicy reports whether the edge should apply the per-proxy
// security policy a client supplies in NEW_PROXY. True ONLY when the edge is in
// standalone mode AND no control plane is wired. A BYOI / managed edge
// (controlPlaneWired=true) NEVER trusts the client — even with mode=standalone —
// so it cannot self-grant paid features or weaken tenant isolation. This is the
// enforced form of the "BYOI = platform semantics" rule.
func (c Config) TrustsClientPolicy(controlPlaneWired bool) bool {
	return c.IsStandaloneMode() && !controlPlaneWired
}

// NormalizeForMode reconciles control-plane wiring with the selected mode and
// returns the effective config plus byoiRefused.
//
//   - platform (or non-standalone): returned unchanged.
//   - standalone + bff-edge configured: this is a BYOI edge holding a
//     control-plane-issued cert → REFUSED standalone, downgraded to platform
//     (byoiRefused=true). The enforced "BYOI = platform semantics" rule.
//   - standalone fork: control-plane addresses (Identity / Tunnel / Cert /
//     Quota / Config) are cleared. config.Default() injects dev-localhost
//     identity/tunnel addrs for the dev stack; clearing them means a config-
//     less community edge neither dials dead services nor mis-trips the trust
//     guard into thinking a control plane is wired.
func (c Config) NormalizeForMode() (cfg Config, byoiRefused bool) {
	if !c.IsStandaloneMode() {
		return c, false
	}
	if c.MultiRegion.IsBFFEdge() {
		c.Mode = "platform"
		return c, true
	}
	c.Identity.Addr = ""
	c.Tunnel.Addr = ""
	c.Cert.Addr = ""
	c.Quota.Addr = ""
	c.Config.Addr = ""
	return c, false
}

// TokenEntry maps a bearer token to a tenant context.
type TokenEntry struct {
	Token       string `yaml:"token"`
	TenantID    string `yaml:"tenant_id"`
	WorkspaceID string `yaml:"workspace_id"`
	ClientID    string `yaml:"client_id"`
}

// LogConfig controls structured-logger behavior.
type LogConfig struct {
	Level  string `yaml:"level"`  // debug/info/warn/error
	Format string `yaml:"format"` // text/json
}

// Default returns a config sane for local development without any file.
//
// Inter-svc addresses point at the dev-cluster localhost ports; ops in prod
// override via a YAML file or env. Without these defaults a freshly-launched
// edge wouldn't report presence (no identity-svc) and wouldn't persist tunnels
// (no tunnel-svc),
// silently degrading two big features — see the 2026-05-27 thread.
func Default() Config {
	return Config{
		NodeID: "edge-dev-1",
		Region: "local",
		Control: ControlListener{
			Addr: ":7443",
		},
		HTTP: HTTPListener{
			Addr:       ":8080",
			BaseDomain: "localtest.me",
		},
		// Serve HTTPS out of the box so new http/https tunnels default to a
		// secure public URL. With BaseDomain set and no platform cert source,
		// the edge generates a self-signed wildcard for this listener (dev /
		// standalone); browsers warn until the generated cert is trusted. A
		// real deployment overrides this (real cert) or clears it via YAML.
		HTTPS: HTTPSListener{
			Addr: ":8443",
		},
		Admin: AdminListener{
			Addr: ":9101",
		},
		Identity: IdentityClient{
			Addr: "127.0.0.1:7001",
		},
		Tunnel: TunnelClient{
			Addr: "127.0.0.1:7003",
		},
		AcceptedTokens: []TokenEntry{
			{
				Token:       "dev-token-please-change",
				TenantID:    "dev",
				WorkspaceID: "default",
				ClientID:    "client-1",
			},
		},
		Log: LogConfig{Level: "info", Format: "text"},
	}
}

// Load reads YAML config from path. If path is empty or the file is missing,
// Default() is returned.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		// An explicitly-requested config path that doesn't exist is almost
		// always a deploy mistake — a wrong volume mount or a -config pointing
		// at a path that isn't mounted into the container. Fail LOUDLY instead
		// of silently returning Default(), whose dev-localhost control-plane
		// addresses make the edge dial 127.0.0.1 with no hint as to why.
		// (Running with NO config is still fine: path=="" returns Default above.)
		return Config{}, fmt.Errorf("read config %q: %w", path, err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

// LookupToken returns the TokenEntry matching token, or false if not found.
func (c *Config) LookupToken(token string) (TokenEntry, bool) {
	for _, t := range c.AcceptedTokens {
		if t.Token == token {
			return t, true
		}
	}
	return TokenEntry{}, false
}
