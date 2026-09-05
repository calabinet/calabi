# Calabi — self-hosting the data plane

**English** · [中文](self-hosting.zh-CN.md)

Calabi's **data plane is open source** — three binaries, and between them two
different ways to reach a machine with no public address:

- `calabi-edge`, which accepts public traffic, and the `calabi` client that
  forwards it to your local services: **tunnels**;
- `calabi-coord` plus `calabi-edge` in its relay role: a private WireGuard
  **mesh** between your own machines. See [The mesh](#the-mesh-connect).

The **control plane** (accounts, orgs, billing, the managed global edge fleet)
is a separate, closed, hosted product. This repository is the data plane on its
own — it never phones home, needs no account, and runs entirely on
infrastructure you own.

If you just want tunnels and you're happy to run one edge yourself, the first
two thirds of this document are all you need.

```
┌─────────────┐        TLS + yamux        ┌──────────────┐      your app
│  calabi     │ ────────────────────────► │  calabi-edge │ ───►  127.0.0.1:8080
│  (client)   │   control + data streams  │  (your VPS)  │
└─────────────┘                           └──────────────┘
   your laptop                            public IP / DNS        visitors ──┘
```

What the hosted Calabi platform adds on top — accounts, a managed global edge
fleet, billing — is listed under *What self-hosting does not give you*,
below.

---

## Build

Requires Go 1.25+.

```bash
# from the repo root
make build       # → bin/calabi-edge, bin/calabi
```

Or directly (on Windows, name the outputs `*.exe`):

```bash
( cd apps/calabi-edge && go build -o calabi-edge ./cmd/calabi-edge )
( cd apps/client      && go build -o calabi      ./cmd/calabi )

calabi version   # → calabi <ver>
```

`make build` adds the `.exe` suffix automatically on Windows. A native build on
Windows is already a Windows binary; to **cross**-compile for another OS, set
`GOOS`/`GOARCH` (e.g. `GOOS=windows GOARCH=amd64 go build -o calabi-edge.exe ./cmd/calabi-edge`).

---

## Quick start (one edge, one tunnel)

**1. Run the edge** on a host with a public IP (or just locally to try it). With
no config file `calabi-edge` runs in `standalone` mode, accepts the demo token,
and listens on `:7443` (control) and `:8080` (HTTP):

```bash
./calabi-edge           # CTRL-C to stop
```

**2. Run a local service** to expose:

```bash
python3 -m http.server 9000
```

**3. Run the client** pointing at your edge:

```bash
export CALABI_SERVER=127.0.0.1:7443       # your edge's control endpoint
export CALABI_TOKEN=dev-token-please-change
export CALABI_INSECURE=1                   # dev: skip TLS verify of a self-signed edge
calabi http 9000 --domain app.localtest.me
```

**4. Visit it** through the edge's HTTP listener:

```bash
curl http://127.0.0.1:8080/ -H 'Host: app.localtest.me'
```

For a real deployment, point a DNS record at the edge's public IP and open the
edge's public ports; see *Production notes* below.

---

## The edge config

The edge reads an optional YAML file (`./calabi-edge --config edge.yaml`). The
fields that matter when you run your own edge:

```yaml
mode: standalone              # self-hosting is always standalone (forced); see below
node_id: my-edge
region: my-region             # cosmetic in a single-edge setup

control:
  addr: ":7443"               # client-facing TLS listener (control + data)
  cert_pem: ""                # path to a TLS cert; empty = self-signed (dev)
  key_pem: ""

http:
  addr: ":8080"               # public HTTP entrypoint (visitors)
  base_domain: tunnel.example.com   # tunnels become <name>.<base_domain>

https:
  addr: ":8443"               # optional HTTPS terminator (see HTTPS below)

state:
  dir: ./state                # persists the subdomain counter + self-signed cert

# Tokens the edge accepts in the client AUTH frame. Each maps to a tenant.
accepted_tokens:
  - token: a-long-random-secret
    tenant_id: "1"
    workspace_id: default
    client_id: client-1
```

- **`mode`** — set it to `standalone` for a self-hosted stack; that is what stops the edge from expecting a managed
  platform to connect to. The edge *trusts the security policy the client
  supplies* in `NEW_PROXY` — which is exactly what you want when you own both ends.
- **`accepted_tokens`** — your auth. Hot-reloadable: edit the file and the edge
  picks it up without a restart (along with `http.base_domain`).
- **`CALABI_EDGE_MODE`** env overrides `mode` without editing YAML.

---

## The client

`calabi http|tcp|udp` open one tunnel each and stay in the foreground.

```bash
calabi http 8080  --domain app.example.com
calabi tcp  22    --remote-port 2222
calabi udp  53    --remote-port 5353
```

Environment:

| var | meaning |
|---|---|
| `CALABI_SERVER` | edge control endpoint `host:port` (default `localhost:7443`) |
| `CALABI_TOKEN` | a token from the edge's `accepted_tokens` |
| `CALABI_INSECURE=1` | skip TLS verification (a self-signed edge) |
| `CALABI_EDGE_CA_FILE` | verify the edge cert against this CA instead |

### Per-tunnel security policy

Every per-tunnel access control ships in this binary: **IP allow/deny** (all
tunnel types), **HTTP Basic auth**, **connection rate limiting**,
**request-header rewrite**, and the **OAuth login wall** (Google / GitHub) —
the last three are HTTP-only. Passwords are bcrypt-hashed **locally** before
they leave your machine:

```bash
calabi http 8080 --domain app.example.com \
  --ip-allow 10.0.0.0/8 --ip-deny 1.2.3.4 \
  --basic-auth alice:s3cret --basic-auth bob:hunter2 \
  --security-file policy.json      # or a full {"security":{…}} blob
```

The edge enforces these (IP allow/deny + Basic auth) for that tunnel.

> A self-hosted edge enforces the same policy set as a managed one. On the
> hosted product these features are gated by plan, and that gate lives in the
> control plane rather than in this code.

---

## The local supervisor daemon (recommended)

Instead of one `calabi http` per terminal, run **all** your tunnels from one
config file in one process, with auto-reconnect:

```bash
calabi daemon --config tunnels.yaml
```

`tunnels.yaml` (see [`docs/examples/tunnels.yaml`](examples/tunnels.yaml) for the
full annotated version):

```yaml
server: edge.example.com:7443
token: ${CALABI_TOKEN}           # literal, or ${ENV_VAR} to read from the env
# insecure: true                 # see TLS note below (omit to verify the cert)
# ca_file: /path/to/edge-ca.pem  # pin the edge's CA to actually verify it
tunnels:
  - name: app
    type: http
    local: 127.0.0.1:8080
    domain: app.example.com
    security:
      ip_allow: ["10.0.0.0/8"]
      basic_auth: ["admin:s3cret"]   # bcrypt-hashed at load
  - name: ssh
    type: tcp
    local: 127.0.0.1:22
    remote_port: 2222
```

Install it as a boot-start OS service (Windows service / systemd / launchd):

```bash
calabi daemon install --config tunnels.yaml   # then: calabi daemon start|stop|status
```

> **Service notes.** The installed service auto-restarts on crash and on boot
> (Windows service `OnFailure=restart`, systemd `Restart=always`, launchd
> `KeepAlive`). When it runs as a service it has no per-user home, so it writes
> its log next to the `calabi` binary (not under your profile). **Changing
> `--config` (or the config path) takes effect only after `calabi daemon
> uninstall` + `install` again** — the launch arguments are baked in at install
> time.

> `tunnels:` can be empty (`tunnels: []`). The daemon still connects and serves
> the console — start with no tunnels and **create them in the browser** (below);
> they're written back to your `tunnels.yaml`.

> **TLS / self-signed edge.** A self-hosted edge is self-signed. The local daemon
> therefore **skips TLS verification of the edge by default** (logging a warning)
> rather than demanding a CA — so it just works on a trusted network. To actually
> verify the edge, set `ca_file:` to its CA PEM (or `CALABI_EDGE_CA_FILE`). Set
> `insecure: true` to skip verification explicitly (silences the warning).

---

## The local web console (`:7400`)

While a tunnel or the local daemon is running, open **http://127.0.0.1:7400** in
your browser for a dashboard:

- live tunnel list with traffic counters,
- a **request inspector** (per-connection log + HTTP request/response capture),
- daemon logs,
- and — with the local daemon — **create / delete tunnels and edit each
  tunnel's security policy live**, written back to your `tunnels.yaml`.

The console talks only to the local daemon (loopback); no account, no
control-plane round-trips. Editing a tunnel's policy re-registers just that
tunnel — your other tunnels keep their connections.

> Console edits rewrite `tunnels.yaml` (your `server` / `token` / TLS settings
> are preserved verbatim — a `token: ${CALABI_TOKEN}` keeps the secret out of the
> file; **comments are not preserved** — a managed-by header is added). If you
> keep the file under version control or with hand comments, prefer editing the
> YAML directly and letting the daemon reload.

---

## HTTPS

A self-hosted edge can terminate HTTPS on `https.addr`, but it needs a
certificate. Options today:

1. **Bring your own cert** — point `control.cert_pem`/`key_pem` (for the control
   listener) and provision the HTTPS cert via `state.dir` or a real cert; good
   for a domain you control.
2. **Self-signed wildcard** (dev) — with `http.base_domain` set and no cert
   source, the edge generates a self-signed wildcard under `state.dir`. Browsers
   warn unless you import it.

> **Known gap:** automatic Let's Encrypt (ACME) on a self-hosted edge is not yet
> implemented — it's on the roadmap. Until then, use one of the options above.

---

## The mesh (Connect)

Tunnels bring the public in. The mesh does the opposite: it joins **your own**
machines into one private WireGuard network — stable `100.64.0.0/10` addresses
that follow a machine across networks, direct peer-to-peer paths where NAT
allows one, and a relay you run yourself where it doesn't.

Three pieces:

| | | |
|---|---|---|
| `calabi-coord` | the coordinator | node registry, address allocation, ACLs, MagicDNS, the relay directory |
| `calabi-edge` with `role: relay` | the relay | forwards **already-encrypted** packets between node keys, and answers STUN so nodes can find their own public endpoint |
| `calabi mesh up` | a node | generates its own WireGuard key, enrolls, brings up a tun device |

The coordinator never sees a private key and never sees plaintext. Neither does
the relay: it routes ciphertext by node key and has no code path that could
decrypt it — that isolation is structural (`pkg/relay` carries no edge or
control-plane code, enforced by a dependency test), not a config option.

### The relay

A relay needs no config file — no domain, no certificate, nothing to terminate:

```bash
CALABI_EDGE_ROLE=relay CALABI_EDGE_RELAY_LABEL=home ./calabi-edge
```

That listens on **3340/tcp** (the relay itself) and **3478/udp** (STUN). Both
must be reachable from your nodes. In YAML instead:

```yaml
role: relay          # or "both" to run a tunnel edge and a relay in one process
relay:
  derp_port: 3340
  stun_port: 3478    # 0 disables the STUN responder
  label: home        # names the region; nodes home on "self-home"
```

> A relay with no `label` starts and warns: it cannot be registered in the relay
> directory, so no node will ever home on it.

Run several in different places if you want; nodes measure latency to each over
STUN and pick their own.

### The coordinator

```bash
CALABI_COORD_AUTHKEYS_FILE=./authkeys.json \
CALABI_COORD_DERP_ADDR=relay.example.com:3340 \
CALABI_COORD_DERP_STUN_PORT=3478 \
./calabi-coord
```

| variable | what it does |
|---|---|
| `CALABI_COORD_GRPC_ADDR` | where nodes connect. Default `:7012` |
| `CALABI_COORD_ADMIN_ADDR` | health + metrics. Default `:9122`; keep it private |
| `CALABI_COORD_AUTHKEYS_FILE` | **the auth keys.** JSON: `{"key": {"meshnet": 1, "tags": ["tag:laptop"]}}` |
| `CALABI_COORD_DERP_ADDR` | one relay, the simple case: `host:port` |
| `CALABI_COORD_DERP_STUN_PORT` | that relay's STUN port. Without it the region cannot be measured, so nobody homes there |
| `CALABI_COORD_DERP_MAP_FILE` | several relays instead: a JSON directory (see `apps/calabi-coord/examples/derp-map.example.json`) |
| `CALABI_COORD_POLICY_FILE` | the ACL file. Unset = every node in a meshnet reaches every other |
| `CALABI_COORD_NODE_QUOTA` | cap on nodes per meshnet. Unset = unlimited |
| `CALABI_COORD_TLS_CERT_FILE` / `_KEY_FILE` | serve gRPC over TLS. Both or neither |
| `CALABI_COORD_MESH_ADMIN_ADDR` / `_TOKEN` | the admin HTTP API. **A tokenless admin surface is refused at startup** — it would expose every meshnet's nodes and ACLs |

A `meshnet` is one isolated network. Two keys mapping to different meshnet
numbers produce two networks on one coordinator that cannot see each other.

> Set `CALABI_ENV=production` and the coordinator refuses to start on any
> fail-open fallback — most importantly the built-in default auth key, which
> admits *any* caller into meshnet 1. Do that on anything reachable from the
> internet.

### Joining a node

```bash
sudo ./calabi mesh up \
  --coord coord.example.com:7012 \
  --relay relay.example.com:3340 \
  --auth-key my-secret-key --name laptop
```

Needs a tun device and privileges. On Windows `wintun.dll` is embedded in the
binary, so there is nothing to install. The node's WireGuard key is generated
locally and cached (`--key-file` to place it); re-running keeps the same
identity and therefore the same `100.64.x.x` address.

`calabi mesh status` and `calabi mesh down` talk to the running daemon over
`:7400`. To run the mesh as a background service instead of in the foreground,
put it in the daemon config and install that as a service:

```yaml
mesh:
  enabled: true
  coord: coord.example.com:7012
  relay: relay.example.com:3340
  auth_key: my-secret-key
  name: laptop
```

> Unlike the tunnel `token:`, `auth_key:` has **no** `${ENV_VAR}` form — it is
> read literally. Keep the file mode tight (it is a credential), or run
> `calabi mesh up` in the foreground with the key on the command line.

> **TLS between node and coordinator.** The node dials the coordinator over TLS
> and verifies it against the CA compiled into the client, so a self-hosted
> coordinator needs one of two things: give it a certificate from your own CA
> (`CALABI_COORD_TLS_CERT_FILE`/`_KEY_FILE`) and point nodes at that CA with
> `CALABI_EDGE_CA_FILE=/path/to/your-ca.pem`, or set `CALABI_INSECURE=1` on the
> nodes for plaintext. **The auth key crosses this connection**, so plaintext is
> for a trusted network only. Started with only one of the two cert variables,
> the coordinator refuses to boot rather than quietly serve plaintext.

### ACLs

Without `CALABI_COORD_POLICY_FILE`, every node in a meshnet reaches every other.
With it, a JSON file of groups and rules decides who reaches whom, on which
ports. It hot-reloads on change — and if the file is broken **it fails closed**
(deny everything) and says so loudly, rather than falling back to allow-all.
Fix the file and it recovers without a restart.

### Subnet routers and exit nodes

```bash
calabi mesh up ... --advertise-routes 192.168.1.0/24   # share a LAN with the mesh
calabi mesh up ... --advertise-exit-node               # offer to be an exit node
calabi mesh up ... --exit-node home-server             # send MY default route out via a peer
```

Advertising works on every platform. The forwarding half — turning on IP
forwarding and NAT so packets actually cross — **is automated on Linux only**;
elsewhere the node advertises and you configure the OS yourself. Taking the
default route as an exit-node *client* works on Linux, Windows and macOS.

### What isn't automated off Linux yet

MagicDNS's OS integration (assigning the resolver and rewriting the system
resolver config) is Linux-only. The mesh works everywhere — node **addresses**
are fine on every platform — but node **names** only resolve through the OS on
Linux.

---

## What self-hosting does *not* give you

These are control-plane features. The commands exist in the binary but need a
managed account to do anything:

- `calabi login / logout / org / certs / domains / clients`,
- the managed presence/CONFIG_PUSH sync daemon (the local supervisor `calabi
  daemon --config …` is the standalone equivalent),
- managed multi-region edge discovery / a global edge fleet,
- accounts, organizations, billing, the web console at console.\<host\>.

These live in the hosted product. The client, the edge and the coordinator in
this repository are a complete, standalone tunneling **and** meshing stack on
their own.

Note what is *not* on that list: the mesh. `calabi-coord` is a full
coordinator, not a demo — its own auth keys, its own ACLs, its own relay
directory. What the hosted platform swaps in is *whose* accounts it trusts
(org identity instead of a key file) and metering; the meshing itself is this
code. The reverse also holds: a self-hosted coordinator is yours alone and
cannot be pointed at the hosted platform's nodes, and platform users never need
to run one.

---

## Production notes

- Put the edge behind a public IP / DNS. Open `control.addr` (clients dial it)
  and `http.addr` / `https.addr` (visitors). Keep `admin.addr`
  (`:9101`, `/metrics` `/healthz`) on a private interface.
- Set `state.dir` to a writable path so the subdomain counter + self-signed cert
  survive restarts.
- Rotate `accepted_tokens` by editing the file (hot-reloaded).
- Process-wide backpressure caps are available via env
  (`EDGE_GLOBAL_MAX_CONNS`, `EDGE_GLOBAL_ACCEPT_RATE_PER_SEC`).
- Run the client/daemon under a service manager (`calabi daemon install`) so it
  restarts on boot.

---

## License & contributing

Open source under the terms in [LICENSE](LICENSE) (see also `NOTICE`). Issues and
patches to the edge core, client core, and the local console are welcome.
