# Calabi — Community Edition (standalone data plane)

Calabi's **data plane is open source**: `calabi-edge`, the edge that accepts
public traffic, and the `calabi` client that forwards it to your local services.
The **control plane** (accounts, orgs, billing, the managed global edge fleet) is
a separate, closed, hosted product. The Community Edition is the data plane on
its own — it never phones home, needs no account, and runs entirely on
infrastructure you own.

If you just want tunnels and you're happy to run one edge yourself, this is all
you need.

```
┌─────────────┐        TLS + yamux        ┌──────────────┐      your app
│  calabi     │ ────────────────────────► │  calabi-edge │ ───►  127.0.0.1:8080
│  (client)   │   control + data streams  │  (your VPS)  │
└─────────────┘                           └──────────────┘
   your laptop                            public IP / DNS        visitors ──┘
```

What the hosted Calabi platform adds on top — accounts, a managed global edge
fleet, billing — is listed under *What the Community Edition does not include*,
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

calabi version   # → calabi <ver> (community edition)
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
mode: standalone              # community is always standalone (forced); see below
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

- **`mode`** — always `standalone` here; the Community Edition has no managed
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

The Community Edition supports two access-control features per tunnel: **IP
allow/deny** (all tunnel types) and **HTTP Basic auth** (`http` only). Passwords
are bcrypt-hashed **locally** before they leave your machine:

```bash
calabi http 8080 --domain app.example.com \
  --ip-allow 10.0.0.0/8 --ip-deny 1.2.3.4 \
  --basic-auth alice:s3cret --basic-auth bob:hunter2 \
  --security-file policy.json      # or a full {"security":{…}} blob
```

The edge enforces these (IP allow/deny + Basic auth) for that tunnel.

> Rate limiting, request-header rewrite, and the OAuth login wall are
> platform-only and not part of the Community Edition — the flags don't exist
> here, and a community edge ignores those blocks if a config carries them.

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

> **TLS / self-signed edge.** A community edge is self-signed. The local daemon
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

The community edge can terminate HTTPS on `https.addr`, but it needs a
certificate. Options today:

1. **Bring your own cert** — point `control.cert_pem`/`key_pem` (for the control
   listener) and provision the HTTPS cert via `state.dir` or a real cert; good
   for a domain you control.
2. **Self-signed wildcard** (dev) — with `http.base_domain` set and no cert
   source, the edge generates a self-signed wildcard under `state.dir`. Browsers
   warn unless you import it.

> **Known gap:** automatic Let's Encrypt (ACME) on the community edge is not yet
> implemented — it's on the roadmap. Until then, use one of the options above.

---

## What the Community Edition does *not* include

These are control-plane features, not part of the Community Edition (the
commands print a "platform-only" notice):

- `calabi login / logout / org / certs / domains / clients`,
- the managed presence/CONFIG_PUSH sync daemon (the local supervisor `calabi
  daemon --config …` is the standalone equivalent),
- managed multi-region edge discovery / a global edge fleet,
- the advanced per-tunnel access controls — connection rate limiting,
  request-header rewrite, and the OAuth (Google/GitHub) login wall (IP allow/deny
  and HTTP Basic auth ARE included),
- accounts, organizations, billing, the web console at console.\<host\>.

These live in the hosted product. The community client + edge are a complete,
standalone tunneling stack on their own.

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
