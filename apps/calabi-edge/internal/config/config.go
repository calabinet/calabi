// Package config loads calabi-edge configuration from YAML or environment.
//
// Schema is intentionally minimal; control-plane integration
// will replace static YAML with config-svc subscriptions.
package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration for calabi-edge.
type Config struct {
	// NodeLabel is this node's human NAME ("lax-1", "sgp-01") — a string the
	// operator picks. Nothing routes on it; it identifies the node to people.
	// It travels to clients in the control handshake, to the edge directory
	// (EdgeNode.node_label), to tunnel-svc (Tunnel.edge_node_label) and into
	// every usage report and log line — where it doubles as the cross-service
	// JOIN key bff-admin uses to line the edge directory up against tunnel
	// counts and metering.
	//
	// Spelled `node_id` until now, which is one character away from
	// `edge_node_id` below and means something entirely different. The edge
	// config was the LAST place still using that name: identity.proto,
	// tunnel.proto and both BFF JSON APIs have called it node_label all along
	// (identity.proto even documents it as "node_label (human edge.yaml
	// node_id)"). `node_id` still loads — see resolveNodeScoped.
	NodeLabel string `yaml:"node_label"`

	// Region is where this node is, and it reaches further than the control
	// plane: a platform relay advertises its DERP region under this exact
	// string. On a node wired to a control plane the certificate names the
	// region too (the CN is edge-{id}-{region}) and RegisterEdgeNode goes by
	// the certificate, so certidentity.go refuses a config that disagrees —
	// but keeps the config's spelling when the two agree, so nothing
	// downstream shifts under a difference in case.
	Region string `yaml:"region"`

	// EdgeNodeID is this node's NUMERIC identity in the control plane: the value
	// tunnels are owned by, port claims are keyed on, config-svc pushes are
	// scoped to, and the mesh resolver compares against to decide whether a
	// tunnel is its own. The counterpart to NodeLabel and NOT derivable from it:
	// NodeLabel is a name an operator chooses, this is a key the control plane
	// assigns. Rule of thumb — label names the node to humans, id addresses it.
	//
	// NOT AN OPERATOR SETTING since 2.0.0. On any node wired to a control plane
	// this is read out of the node's own mTLS certificate, because that is where
	// the control plane reads it from too — see certidentity.go, which also
	// refuses to start a node whose config disagrees with its certificate. A
	// config that still names it is accepted for one version and warned about.
	//
	// Zero on a standalone / dev node, which has no certificate and nobody
	// keying anything on its id; main.go then hashes NodeLabel so the number is
	// at least stable across restarts.
	EdgeNodeID int64 `yaml:"edge_node_id"`

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

	// Role selects which of the two SERVICES this node provides:
	//   "tunnel" (default; empty) — tunnels only, exactly today's calabi-edge.
	//   "mesh"                    — the mesh relay datapath only.
	//   "both"                    — one process serving both.
	// The mesh datapath is ciphertext-only and NEVER crosses the edge's TLS
	// termination. Empty defaults to
	// "tunnel" so every existing node is unchanged.
	//
	// The values name the SERVICE, not the machinery: "edge" said nothing inside
	// a binary called calabi-edge, and once the relay merged in, the question
	// this field answers stopped being "which binary am I" and became "which of
	// the two products do I serve". They are the same two words the product uses
	// everywhere else.
	//
	// "edge" and "relay" are still accepted, permanently. `CALABI_EDGE_ROLE=relay`
	// is the copy-paste line in the PUBLISHED self-hosting guide for running an
	// extra relay, so it is already baked into strangers' systemd units and
	// scripts, where we cannot see it and cannot migrate it. Dropping it would
	// stop their relay the moment they pulled a new image. (Our own shipped
	// bundle, deploy/server, says role: both and is unaffected either way.)
	// See roleAliases.
	Role string `yaml:"role"`

	// OrgID is the organization this node belongs to: which org's certificates
	// it fetches to serve (certclient) and, for a self-hosted relay, which org
	// its traffic is billed to. Here rather than under either service because
	// both read it.
	//
	// NOT FROM THE FILE — hence yaml:"-". It comes from this node's own mTLS
	// certificate (certidentity.go): a BYOI node's carries a SPIFFE org SAN,
	// which is the same place bff-edge reads the org it stamps onto everything
	// this node reports. Both spellings the file ever had (`org_id` and
	// `cert.org_id`) are refused — see layout.go.
	//
	// ZERO means a PLATFORM node, which serves every org rather than none. Its
	// certificate carries no org SAN, and bff-edge turns that into an all-org
	// cert listing (ListCerts all_orgs). Anything reading this field must treat
	// 0 as "all", never as a lookup key.
	OrgID int64 `yaml:"-"`

	// Shared by both services, or by neither (process-level).
	Admin       AdminListener     `yaml:"admin"`
	State       StateConfig       `yaml:"state"`
	Public      PublicConfig      `yaml:"public"`
	MultiRegion MultiRegionConfig `yaml:"multi_region"`
	Log         LogConfig         `yaml:"log"`

	// Tunnel is everything only the TUNNEL service reads, and Mesh everything
	// only the MESH service reads. A node with role: mesh can delete the whole
	// tunnel: block and lose nothing — which is the property the split exists
	// for, since before it a relay-only config was indistinguishable from an
	// edge's at a glance.
	Tunnel TunnelService `yaml:"tunnel"`
	Mesh   MeshService   `yaml:"mesh"`

	// CoordPubKey / CoordPubKeyFile name the coordinator this edge belongs to: the base64 Ed25519 key
	// its grants are signed with, inline or in a file the coordinator writes
	// (CALABI_COORD_GRANT_PUBKEY_FILE, on a volume the two share). A
	// standalone edge accepts devices by those grants and nothing else, for
	// tunnels and relay alike. relay.coord_pubkey is the older spelling of the
	// inline key and is kept equal to it (resolveCoordPubKey).
	CoordPubKey     string `yaml:"coord_pubkey"`
	CoordPubKeyFile string `yaml:"coord_pubkey_file"`
}

// TunnelService is everything only the tunnel data plane reads: where it
// listens, what it is called on the public internet, and the certificates it
// serves. A node running role: mesh reads none of it.
//
// Every one of these was a top-level key before 2.0.0, and all of them still
// load from there (migrateLayout).
type TunnelService struct {
	// BaseDomain is the wildcard domain this node serves — u<N>.<base_domain>.
	// The subdomain allocator, the TCP endpoint namer, the HTTPS self-signed
	// wildcard, the control handshake and the owner cache all read it. MUST
	// also appear in TUNNEL_SVC_BASE_DOMAINS on the control plane, or tunnel-svc
	// won't treat these subdomains as platform-managed.
	BaseDomain string `yaml:"base_domain"`

	// PORTS, not addresses. Every one of these was an `addr` — `control.addr:
	// ":7443"` — and in every config ever deployed the host half was empty,
	// because all four listeners have to be reachable from outside the machine.
	// So they said "port" while looking like "address", and sat among the four
	// settings that ARE addresses (public, admin, peer_forward.advertise_addr,
	// multi_region.bff_edge_addr) with nothing to tell them apart. Where this
	// node can be reached is now one setting, public.host, and each service
	// names only the port it wants — which is what mesh: already did.
	//
	// A zero port turns a listener off, which is what an empty addr did.
	//
	// The cost, chosen deliberately: an external port can no longer differ from
	// the bound one. Nothing we deploy does that, and a node behind such a
	// mapping can bind the external port directly.
	ControlPort int `yaml:"control_port"`
	// ControlCertPEM / ControlKeyPEM are the control listener's certificate —
	// what a client checks before it sends this node anything. Empty means
	// self-signed (see resolveControlCert), or, on a node whose own certificate
	// can serve inbound, that certificate (see certidentity.go).
	ControlCertPEM string `yaml:"control_cert_pem"`
	ControlKeyPEM  string `yaml:"control_key_pem"`

	HTTPPort  int `yaml:"http_port"`
	HTTPSPort int `yaml:"https_port"`
	// HTTPSSelfSigned lets the HTTPS terminator fall back to a self-signed
	// wildcard for BaseDomain when no real certificate covers the requested SNI.
	// DEV ONLY: in production a missing certificate must fail the handshake
	// rather than serve an untrusted one.
	HTTPSSelfSigned bool `yaml:"https_self_signed"`
	SNIPort         int  `yaml:"sni_port"`

	// PeerForward is edge-to-edge forwarding of TUNNEL traffic. It is
	// here, and not next to the mesh, because that is what it forwards. It keeps
	// addresses rather than ports: advertise_addr is deliberately a DIFFERENT,
	// VPC-internal address, not this node's public one, so there is nothing to
	// collapse into public.host.
	PeerForward PeerForwardConfig `yaml:"peer_forward"`
}

// ControlAddr / HTTPAddr / HTTPSAddr / SNIAddr render a port as the bind string
// the listeners take. Zero yields "", which every listener reads as "off".
func (t TunnelService) ControlAddr() string { return bindAddr(t.ControlPort) }
func (t TunnelService) HTTPAddr() string    { return bindAddr(t.HTTPPort) }
func (t TunnelService) HTTPSAddr() string   { return bindAddr(t.HTTPSPort) }
func (t TunnelService) SNIAddr() string     { return bindAddr(t.SNIPort) }

func bindAddr(port int) string {
	if port <= 0 {
		return ""
	}
	return ":" + strconv.Itoa(port)
}

// AdvertisedAddr is what this node registers as its dial string: the one host
// it publishes, plus the port its control listener binds. Empty when either is
// missing — a node that cannot say where it is does not get to guess.
func (c Config) AdvertisedAddr() string {
	host := strings.TrimSpace(c.Public.Host)
	if host == "" || c.Tunnel.ControlPort <= 0 {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(c.Tunnel.ControlPort))
}

// MeshService is everything only the mesh relay reads. Spelled `relay:` before
// 2.0.0, which still loads (migrateLayout).
//
// The BLOCK is named for the service and its FIELDS for the machinery, which is
// the same split as `role: mesh` being served by a relay: DERP and STUN ports
// are relay mechanics, and calling them mesh ports would describe nothing.
type MeshService struct {
	DERPPort int `yaml:"derp_port"` // TCP relay port mesh nodes dial; default 3340
	STUNPort int `yaml:"stun_port"` // UDP STUN responder port; default 3478 (0 disables)
	// Label names the DERP region this node advertises: region code = "self-"+Label.
	Label string `yaml:"label"`
	// Kind is "self" (default — a BYOI node's relay is the org's self-hosted relay)
	// or "platform". Drives R0' grant-scope acceptance.
	Kind string `yaml:"kind"`
	// RequireAuth enforces R0' grants (reject connections without a valid one).
	RequireAuth bool `yaml:"require_auth"`
	// CoordPubKey is the older spelling of the top-level coord_pubkey, kept
	// equal to it (resolveCoordPubKey).
	CoordPubKey string `yaml:"coord_pubkey"`
}

// AdminListener configures the operational HTTP surface (/healthz, /readyz,
// /metrics). Should bind to a private interface in prod; never serve tenant
// traffic on this socket.
type AdminListener struct {
	Addr string `yaml:"addr"` // e.g. ":9101"
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
	// Host is where this node can be reached from outside it — a name or an IP,
	// no port. Every port this node listens on is named by the service that
	// wants it, so this is the one place the ADDRESS is written.
	//
	// It reaches clients (the dial string in the edge directory is this host
	// plus tunnel.control_port), devices (a relay's endpoint is this host plus
	// mesh.derp_port) and the self-signed control certificate's SAN. Spelled
	// `public.addr`, with the control port repeated in it, before 2.0.0.
	Host string `yaml:"host"`
}

// PeerForwardConfig configures intra-region edge HA. When both
// fields are set this edge participates in same-region peer forwarding:
//   - it registers AdvertiseAddr as its `internal_addr` in the edge
//     directory (ListEdges), so peers know where to relay to;
//   - it listens on ForwardAddr for visitor connections relayed by a
//     peer edge that received traffic for a tunnel THIS edge owns.
//
// Empty (default) = single-edge region / disabled: no peer listener, no
// internal_addr advertised, behaves exactly. Cross-region
// forwarding never happens — peers are only ever same-region edges (the owner
// registry + ListEdges are region-scoped).
//
// This block was called `mesh:` until 2.0.0, which was a straight collision:
// it forwards TUNNEL traffic between two edges and has nothing to do with the
// WireGuard mesh, so the type carried a comment disclaiming the name and
// `role: mesh` would have put a third meaning of the word in the same file.
// The old `mesh:` spelling is REFUSED rather than migrated (layout.go): it and
// the mesh-relay block cannot be told apart except by guessing from their
// fields, and reading one as the other would take a node out of its region's
// forwarding pool in silence. The error names the new spelling.
type PeerForwardConfig struct {
	// ForwardAddr is the VPC-internal bind addr for the peer-forward
	// listener, e.g. ":7090". MUST be reachable only inside the region's
	// VPC (security-group gated); never exposed to the public SLB.
	ForwardAddr string `yaml:"forward_addr"`
	// AdvertiseAddr is the VPC-internal host:port a peer dials to reach
	// ForwardAddr, e.g. "10.0.1.5:7090" or "edge-a.calabi.svc:7090".
	// Registered as internal_addr in the edge directory.
	AdvertiseAddr string `yaml:"advertise_addr"`
}

// PeerForwardEnabled reports whether this edge participates in peer forwarding.
// Both bind + advertise addrs must be set; either blank = disabled.
func (c Config) PeerForwardEnabled() bool {
	return c.Tunnel.PeerForward.ForwardAddr != "" && c.Tunnel.PeerForward.AdvertiseAddr != ""
}

// roleAliases maps every spelling this node accepts to the current one. The
// retired spellings are kept for good: see the note on Config.Role.
//
// One map rather than a case list per method, because the failure this prevents
// is the two methods disagreeing — a role that satisfies NEITHER runs no data
// plane at all, and a role that satisfies BOTH silently binds tunnel listeners
// on a node the operator believes is relay-only.
var roleAliases = map[string]string{
	"":       "tunnel", // unset: unchanged behaviour for every existing node
	"tunnel": "tunnel",
	"edge":   "tunnel", // retired spelling
	"mesh":   "mesh",
	"relay":  "mesh", // retired spelling
	"both":   "both",
}

// role is the normalised role: one of "tunnel", "mesh", "both", or "" when the
// operator wrote something this node does not recognise (ValidateRole refuses
// to start on that, so the data-plane predicates never see it in practice).
func (c Config) role() string {
	return roleAliases[strings.ToLower(strings.TrimSpace(c.Role))]
}

// ServesMesh reports whether this node runs the mesh relay datapath.
func (c Config) ServesMesh() bool {
	r := c.role()
	return r == "mesh" || r == "both"
}

// ServesTunnels reports whether this node runs the tunnel datapath. Empty role
// means tunnels, so every existing calabi-edge keeps its exact behaviour.
func (c Config) ServesTunnels() bool {
	r := c.role()
	return r == "tunnel" || r == "both"
}

// ValidateRole rejects a typo'd role rather than silently running neither data
// plane (ServesTunnels && ServesMesh both false).
func (c Config) ValidateRole() error {
	if _, ok := roleAliases[strings.ToLower(strings.TrimSpace(c.Role))]; ok {
		return nil
	}
	return fmt.Errorf("invalid role %q: want tunnel, mesh, or both "+
		"(the earlier names edge and relay still work)", c.Role)
}

// ValidatePublicHost requires a node that serves tunnels to name the host it is
// reachable at.
//
// It used to be optional, with public.addr falling back to the control
// listener's BIND address. On one machine ":7443" happens to work as a dial
// string, which is why that fallback survived; anywhere else it registered the
// node as reachable at an address nothing could reach, and the node looked
// healthy the whole time. Every config we have ever deployed sets it.
//
// Not required on a node that serves no tunnels: a relay is found through the
// coordinator's DERP map, which names it there. It is still worth setting —
// a relay that self-registers needs it — and the platform path warns when it
// is missing.
func (c Config) ValidatePublicHost() error {
	if !c.ServesTunnels() || strings.TrimSpace(c.Public.Host) != "" {
		return nil
	}
	return fmt.Errorf("public.host is required on a node that serves tunnels: it is the address " +
		"clients dial and the name the control certificate is issued for. Set it to a host or IP " +
		"that reaches this node from outside it (the port comes from tunnel.control_port)")
}

// ValidateClientAuth rejects an edge that could accept no client. On the
// platform bff-edge verifies clients. Anywhere else the edge belongs to a
// self-hosted coordinator and accepts devices by its grants, so it must say so
// (mode: standalone) and name the coordinator's key. Such an edge would
// otherwise start cleanly and turn every device away.
func (c Config) ValidateClientAuth() error {
	if c.MultiRegion.IsBFFEdge() {
		return nil
	}
	if c.ServesTunnels() && !c.IsStandaloneMode() {
		return fmt.Errorf("no control plane verifies clients here (multi_region is not bff-edge): an edge that " +
			"belongs to a self-hosted coordinator says mode: standalone and names the coordinator's key " +
			"(coord_pubkey or coord_pubkey_file; `calabi-coord pubkey` prints it)")
	}
	if c.IsStandaloneMode() && strings.TrimSpace(c.CoordPubKey) == "" && strings.TrimSpace(c.CoordPubKeyFile) == "" {
		return fmt.Errorf("mode: standalone needs the coordinator's public key (coord_pubkey, or coord_pubkey_file " +
			"where the coordinator writes it; `calabi-coord pubkey` prints it): its grants are the only way a " +
			"device gets in, for tunnels and relay alike")
	}
	return nil
}

// resolveCoordPubKey keeps the two spellings of the coordinator's inline key
// equal: mesh.coord_pubkey (spelled relay.coord_pubkey before 2.0.0) came
// first, when only the relay checked grants. Setting both to different values,
// or an inline key and a key file, is refused rather than picking one.
func resolveCoordPubKey(c *Config) error {
	top, relay := strings.TrimSpace(c.CoordPubKey), strings.TrimSpace(c.Mesh.CoordPubKey)
	switch {
	case top != "" && relay != "" && top != relay:
		return fmt.Errorf("coord_pubkey and mesh.coord_pubkey name different keys; keep coord_pubkey")
	case top == "":
		top = relay
	}
	if top != "" && strings.TrimSpace(c.CoordPubKeyFile) != "" {
		return fmt.Errorf("coord_pubkey and coord_pubkey_file are both set; give the coordinator's key one way")
	}
	c.CoordPubKey, c.Mesh.CoordPubKey = top, top
	return nil
}

// IsPlatformKind reports whether this relay is a platform (multi-tenant) relay
// rather than a self-hosted one. Mirrors relayAuthConfig's parsing exactly:
// empty / "self" / "self-hosted" is self-hosted, only "platform" is platform.
// It decides how relay usage is attributed — a platform relay bills PER org from
// each node's grant, a self-hosted one bills its single org under a "self-" region.
func (r MeshService) IsPlatformKind() bool {
	return strings.EqualFold(strings.TrimSpace(r.Kind), "platform")
}

// RelayDERPPort / RelaySTUNPort apply calabi-derp's defaults when unset.
func (r MeshService) RelayDERPPort() int {
	if r.DERPPort == 0 {
		return 3340
	}
	return r.DERPPort
}

func (r MeshService) RelaySTUNPort() int {
	if r.STUNPort == 0 {
		return 3478
	}
	return r.STUNPort
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
//     Quota / Config) are cleared, so an edge that inherited them from a
//     platform config it was adapted from neither dials dead services nor
//     mis-trips the trust guard into thinking a control plane is wired.
//     (Default() no longer seeds any of them — see its comment.)
func (c Config) NormalizeForMode() (cfg Config, byoiRefused bool) {
	if !c.IsStandaloneMode() {
		return c, false
	}
	if c.MultiRegion.IsBFFEdge() {
		c.Mode = "platform"
		return c, true
	}
	// A standalone edge belongs to a coordinator and its relay serves that
	// coordinator's devices only: grants are required, whatever the file says.
	c.Mesh.RequireAuth = true
	return c, false
}

// LogConfig controls structured-logger behavior.
type LogConfig struct {
	Level  string `yaml:"level"`  // debug/info/warn/error
	Format string `yaml:"format"` // text/json
}

// Default returns a config sane for local development without any file.
//
// It sets NO inter-service address. It used to seed the dev cluster's localhost
// identity/tunnel ports so a bare `calabi-edge` would report presence and persist
// tunnels; a6d97bcf (F3: the edge reaches the control plane only through
// bff-edge) removed them. So a config-less edge dials nothing, which is also
// what makes the self-hosting docs' "it never phones home" true of the default
// build and not just of a hand-written config.
//
// Note what this does NOT set: Mode, or any way to accept a client. A
// config-less edge is therefore refused at start (ValidateClientAuth) unless the
// environment makes it a relay, or a standalone edge that names its coordinator.
// It used to carry a demo token for a config-less quick start; the static token
// table is gone.
func Default() Config {
	return Config{
		NodeLabel: "edge-dev-1",
		Region:    "local",
		Tunnel: TunnelService{
			BaseDomain:  "localtest.me",
			ControlPort: 7443,
			HTTPPort:    8080,
			// Serve HTTPS out of the box so new http/https tunnels default to a
			// secure public URL. With BaseDomain set and no platform cert source,
			// the edge generates a self-signed wildcard for this listener (dev /
			// standalone); browsers warn until the generated cert is trusted. A
			// real deployment overrides this (real cert) or clears it via YAML.
			HTTPSPort: 8443,
		},
		Admin: AdminListener{
			Addr: ":9101",
		},
		Log: LogConfig{Level: "info", Format: "text"},
	}
}

// Load reads YAML config from path. If path is empty or the file is missing,
// Default() is returned.
func Load(path string) (Config, error) {
	cfg, _, err := loadWithRaw(path)
	return cfg, err
}

// loadWithRaw is Load plus the RAW parse: the same bytes decoded over a zero
// Config, where a non-empty field means the file actually said so. Several
// checks need that distinction and cannot get it from the merged config,
// because Default() pre-fills region, node_label and the base domain.
//
// Load hands the raw parse back rather than keeping it to itself so that the
// steps AFTER it — resolveCertIdentity, in LoadEffective — can tell "the
// operator wrote this" from "Default() filled it in" too. The first draft of
// the certificate check read the merged config and refused every platform edge
// on the spot: Default() says region "local", no certificate ever will.
func loadWithRaw(path string) (Config, Config, error) {
	cfg := Default()
	if path == "" {
		// Nothing was written, so the raw parse is empty by construction.
		return cfg, Config{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		// An explicitly-requested config path that doesn't exist is almost
		// always a deploy mistake — a wrong volume mount or a -config pointing
		// at a path that isn't mounted into the container. Fail LOUDLY instead
		// of silently returning Default(), whose dev-localhost control-plane
		// addresses make the edge dial 127.0.0.1 with no hint as to why.
		// (Running with NO config is still fine: path=="" returns Default above.)
		return Config{}, Config{}, fmt.Errorf("read config %q: %w", path, err)
	}
	// One layout from here on. migrateLayout rewrites a pre-1.15 document into
	// the current shape (and refuses one it cannot rewrite unambiguously), so
	// nothing below — the decode, the role guard, the hot-reload comparison —
	// has to know two layouts. See layout.go.
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return Config{}, Config{}, fmt.Errorf("parse config: %w", err)
	}
	if err := migrateLayout(&doc); err != nil {
		return Config{}, Config{}, err
	}
	migrated, err := yaml.Marshal(&doc)
	if err != nil {
		return Config{}, Config{}, fmt.Errorf("parse config: %w", err)
	}
	if err := yaml.Unmarshal(migrated, &cfg); err != nil {
		return Config{}, Config{}, fmt.Errorf("parse config: %w", err)
	}
	// raw is the same bytes over a ZERO Config, so a non-empty field in it means
	// the file actually said so. Default() pre-fills tunnel.http.base_domain,
	// which is why the checks below cannot read the merged cfg.
	var raw Config
	if err := yaml.Unmarshal(migrated, &raw); err != nil {
		return Config{}, Config{}, fmt.Errorf("parse config: %w", err)
	}
	// A token table the edge would now ignore (see obsolete.go).
	if err := checkRemovedTokens(data); err != nil {
		return Config{}, Config{}, err
	}
	// Role assertions that need to tell "the operator wrote this" from
	// "Default() filled it in", hence the raw parse. See roleguard.go.
	if err := checkRoleConfig(cfg, raw); err != nil {
		return Config{}, Config{}, err
	}
	// A merged node's relay region defaults to the node's own region, so a node
	// needs no identifier separate from the region the operator already named it:
	// a self-hosted relay's code reads self-<region>, a platform relay's code IS
	// that region (the coordinator lists this same region from the edge directory,
	// so the two can't drift). mesh.label overrides it only when a node must
	// advertise a region distinct from its own — e.g. two relays sharing one
	// region. Resolving here (not at each use) means every downstream reader — map
	// registration, usage attribution, the startup warning, the relay log — sees
	// the effective label with no special-casing.
	if cfg.ServesMesh() && strings.TrimSpace(cfg.Mesh.Label) == "" {
		cfg.Mesh.Label = strings.TrimSpace(cfg.Region)
	}
	return cfg, raw, nil
}
