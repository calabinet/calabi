# Calabi — self-hosting

**English** · [中文](self-hosting.zh-CN.md)

A self-hosted Calabi server is two programs. Each of your devices runs the
client.

- `calabi-coord`, the coordinator — devices join it with an invite and get a
  `100.64.x.x` address. It keeps the list of devices, the ACLs and the invites,
  and tells each device where the edge is.
- `calabi-edge`, the edge — takes public traffic for your **tunnels**, and
  relays **mesh** traffic between devices that cannot connect directly.
- `calabi`, the client — runs tunnels and joins the private WireGuard mesh.

A device joins once. From then on it has tunnels and the mesh. The mesh can be
switched off on a device while its tunnels keep running.

```
                        ┌────────────────┐
     joins; gets the    │  calabi-coord  │  devices, addresses, ACLs, invites
     edge and a grant   │  (your server) │
          ┌────────────►└────────────────┘
          │
    ┌─────┴─────┐   tunnels   ┌────────────────┐
    │  calabi   │ ──────────► │  calabi-edge   │ ◄──── visitors (HTTP / TCP / UDP)
    │ (device)  │             │  (your server) │
    └─────┬─────┘             └────────────────┘
          │  WireGuard: direct, or through the edge's relay
          ▼
    your other devices
```

A self-hosted server needs no account and connects to no service of ours. The
Android app (`apps/client-android`) and the client's console join it too — see
[Phones and the desktop console](#phones-and-the-desktop-console).

## Contents

- [Quick start: your server in Docker](#quick-start-your-server-in-docker)
- [Get the binaries](#get-the-binaries)

**Your server**

- [The coordinator](#the-coordinator) — [its certificate](#the-coordinators-certificate)
- [The edge](#the-edge) — [HTTPS](#https), [a relay on its own](#a-relay-on-its-own)
- [Invites and devices](#invites-and-devices)
- [Coordinator and edge on different machines](#coordinator-and-edge-on-different-machines)

**Devices**

- [Joining](#joining)
- [Tunnels](#tunnels) — [security policy](#per-tunnel-security-policy), [the daemon](#the-daemon), [the console](#the-local-web-console-7400)
- [The mesh](#the-mesh) — [ACLs](#acls), [subnet routers and exit devices](#subnet-routers-and-exit-devices)
- [Phones and the desktop console](#phones-and-the-desktop-console)

**Then**

- [Only on calabi.net](#only-on-calabinet)
- [Production notes](#production-notes)
- [Upgrading to 2.0](#upgrading-to-20)
- [Upgrading from 1.12 or earlier](#upgrading-from-112-or-earlier)
- [Questions](#questions)
- [License & contributing](#license--contributing)

---

## Quick start: your server in Docker

On a Linux machine with a public address and Docker Compose (or
`podman compose`), [`deploy/server`](../deploy/server) runs the coordinator and
the edge together from one `.env`:

```bash
cd deploy/server
cp .env.example .env     # CALABI_PUBLIC_HOST, CALABI_ADMIN_TOKEN, and CALABI_TUNNEL_DOMAIN for HTTP tunnels
docker compose up -d
docker compose exec coord calabi-coord invite --note "my laptop"
```

Open these ports to the internet:

| port | for |
|---|---|
| 7012/tcp | devices ↔ the coordinator |
| 7443/tcp | devices' tunnel connections |
| 80/tcp, 443/tcp | visitors to HTTP tunnels |
| 20000–20999/tcp and /udp | visitors to TCP and UDP tunnels |
| 3340/tcp, 3478/udp | the mesh relay, and STUN |

HTTP tunnels also need a wildcard DNS record for the tunnel domain
(`*.tunnels.example.com`) pointing at the machine.

On a computer, join with the link the invite printed, then open a tunnel:

```bash
calabi join "calabi://join?…"
calabi http 8080
```

On a phone, scan the invite's QR code in the Calabi app.

Managing devices, updates and backups of the bundle: its
[README](../deploy/server/README.md). The rest of this page covers each part and
every setting.

---

## Get the binaries

The [releases page](https://github.com/calabinet/calabi/releases) has all three
for Linux (amd64, arm64, armv7), macOS (amd64, arm64) and Windows (amd64,
arm64), with a `build-manifest.json` for rebuilding them from this source. There
are docker images too (amd64, arm64): `calabinet/calabi-coord`,
`calabinet/calabi-edge` and `calabinet/calabi`.

To build them yourself (Go 1.25+):

```bash
# from the repo root
make build       # → bin/calabi, bin/calabi-edge, bin/calabi-coord
```

Or directly (on Windows, name the outputs `*.exe`):

```bash
( cd apps/client       && go build -o calabi       ./cmd/calabi )
( cd apps/calabi-edge  && go build -o calabi-edge  ./cmd/calabi-edge )
( cd apps/calabi-coord && go build -o calabi-coord ./cmd/calabi-coord )
```

To cross-compile, set `GOOS`/`GOARCH` (e.g.
`GOOS=windows GOARCH=amd64 go build -o calabi-edge.exe ./cmd/calabi-edge`).

Run the same release on the coordinator, the edge and the devices. Devices need
1.13 or later to join.

---

## The coordinator

```bash
CALABI_COORD_DB_DSN=sqlite:./coord.db \
CALABI_COORD_MESH_ADMIN_ADDR=127.0.0.1:9500 \
CALABI_COORD_MESH_ADMIN_TOKEN=a-long-random-secret \
CALABI_COORD_PUBLIC_ADDR=server.example.com:7012 \
CALABI_COORD_EDGE_ADDR=server.example.com:7443 \
CALABI_COORD_GRANT_PUBKEY_FILE=./coord.pub \
CALABI_COORD_DERP_ADDR=server.example.com:3340 \
CALABI_COORD_DERP_STUN_PORT=3478 \
./calabi-coord
```

| variable | what it does |
|---|---|
| `CALABI_COORD_GRPC_ADDR` | where devices connect. Default `:7012` |
| `CALABI_COORD_PUBLIC_ADDR` | the address devices dial, `host:port`. Invite links carry it |
| `CALABI_COORD_DB_DSN` | where it keeps its state: `sqlite:./coord.db`, or a `postgres://…` URL. Unset = in memory (see below) |
| `CALABI_COORD_MESH_ADMIN_ADDR` / `_TOKEN` | the admin API that `calabi-coord invite`, `authkey` and `device` use. Keep it on a private address. The token is required |
| `CALABI_COORD_ADMIN_ADDR` | health and metrics. Default `:9122`; keep it private |
| `CALABI_COORD_EDGE_ADDR` | the edge devices use for tunnels: `host:port` of its control listener |
| `CALABI_COORD_EDGE_PIN` | the edge's certificate fingerprint (`calabi-edge -fingerprint`). Unset = the coordinator reads it from the edge ([how](#how-do-devices-trust-the-edges-certificate)) |
| `CALABI_COORD_EDGE_TRUST` | `system` for an edge with a publicly trusted certificate: devices check it against their system roots |
| `CALABI_COORD_EDGE_PROBE_ADDR` | where the coordinator reaches the edge to read its certificate, when that differs from `EDGE_ADDR` (`127.0.0.1:7443` on one machine, `edge:7443` in a compose network) |
| `CALABI_COORD_RELAY_GRANT_KEY_FILE` | the key it signs devices' [grants](#what-is-a-grant) with. Default `./coord-grant.key`, created on first start |
| `CALABI_COORD_GRANT_PUBKEY_FILE` | a file it writes the public half of that key to at every start, for the edge to read |
| `CALABI_COORD_DERP_ADDR` | one relay, `host:port` |
| `CALABI_COORD_DERP_STUN_PORT` | that relay's STUN port. Devices choose their relay by measuring it over STUN, so set it |
| `CALABI_COORD_DERP_HOME_REGION` | the region name of `CALABI_COORD_DERP_ADDR` (default `default`); with a map file that sets no `home_region`, the region new devices start on |
| `CALABI_COORD_DERP_MAP_FILE` | several relays: a JSON file (see `apps/calabi-coord/examples/derp-map.example.json`) |
| `CALABI_COORD_AUTHKEYS_FILE` | your own permanent keys, optional. JSON: `{"key": {"meshnet": 1, "tags": ["tag:laptop"]}}` |
| `CALABI_COORD_POLICY_FILE` | the [ACL](#acls) file. Unset = every device in a meshnet reaches every other |
| `CALABI_COORD_NODE_QUOTA` | the most devices per meshnet. Unset or `0` = no limit |
| `CALABI_COORD_TLS_CERT_FILE` / `_KEY_FILE` | your own certificate, both or neither. Neither = a self-signed one ([its certificate](#the-coordinators-certificate)) |
| `CALABI_COORD_TLS_DIR` | where the self-signed certificate is kept. Default `./coord-tls` |
| `CALABI_COORD_TLS` | `off` serves plaintext |

**A database.** Set `CALABI_COORD_DB_DSN`; `sqlite:./coord.db` is enough.
Without one, the coordinator keeps devices, ACLs, services and relays in memory:
after a restart every device joins again and gets a new address. A DSN that does
not work stops the coordinator from starting.

**Files to keep.** `coord-grant.key`, the `coord-tls/` directory and the
database. A new `coord-grant.key` means the edge turns every device away until
it has the new public half (`calabi-coord pubkey` prints it).

**Meshnets.** Every key belongs to a meshnet, a number. Devices in different
meshnets are separate networks on the same coordinator.

**Trying it out.** With neither a key file nor a database, the coordinator
accepts the key `dev-meshnet-1-key` into meshnet 1.

**`CALABI_ENV=production`.** Set it on a coordinator reachable from the
internet. It then refuses to start with an open default: it needs a key file or
a database (the built-in key is off), and `CALABI_COORD_NODE_QUOTA` set (`0` for
no limit).

### The coordinator's certificate

The coordinator serves TLS. Without `CALABI_COORD_TLS_CERT_FILE`/`_KEY_FILE` it
makes a self-signed certificate on its first start and keeps it in
`CALABI_COORD_TLS_DIR`. `calabi-coord fingerprint` prints its fingerprint, and
invites carry it. Keep the directory: a new certificate has to be confirmed on
every device.

How a device checks the coordinator's certificate (`trust:` in its config,
`--trust` for `calabi mesh up`):

| trust | checks | set with |
|---|---|---|
| `pin` | the certificate's key against a fingerprint; not the host name | the fingerprint in an invite, `pins:`, `--pin` |
| `system` | the operating system's trusted roots and the host name — for a certificate from Let's Encrypt or another public CA | the default when an invite carries no fingerprint |
| `ca` | your own CA only, and the host name | `ca_file:`, `--ca-file` |
| `plaintext` | nothing | `trust: plaintext`, `--trust plaintext` |

`CALABI_COORD_TLS=off` serves plaintext, for a network you trust or behind a
proxy that terminates TLS. Invites for it need
`calabi-coord invite --allow-plaintext`. To type its address into an app, tick
**No encryption**.

---

## The edge

The edge reads a YAML file (`./calabi-edge -config edge.yaml`):

```yaml
# --- this node: who it is, whose it is, what it runs ---
mode: standalone             # belongs to your coordinator; required
role: both                   # tunnel | mesh | both
coord_pubkey_file: ./coord.pub   # the coordinator's grant key (or coord_pubkey: <base64>)
node_label: my-server        # this node's name in its logs

public:
  host: server.example.com   # where this node is reached; required if it serves tunnels

admin:
  addr: "127.0.0.1:9101"     # /healthz + /metrics — keep it private
state:
  dir: ./state               # the subdomain counter and the self-signed certificates

# --- only the TUNNEL service reads this ---
tunnel:
  base_domain: tunnels.example.com  # HTTP tunnels become <name>.<base_domain>
  control_port: 7443         # the calabi client connects here
  control_cert_pem: ""       # a certificate; empty = self-signed, kept in state.dir
  control_key_pem: ""
  http_port: 80              # visitors
  https_port: 443            # see HTTPS below

# --- only the MESH relay reads this ---
mesh:
  derp_port: 3340            # the relay
  stun_port: 3478            # 0 turns STUN off
  label: my-server           # this relay's name in its logs
```

A node with `role: mesh` can delete the whole `tunnel:` block, and one with
`role: tunnel` the whole `mesh:` block. That is what the two blocks are for: the
file says which half of the program this machine runs.

- **`mode: standalone`** — required. The edge admits devices with your
  coordinator's grants, applies each tunnel's security policy, and lets clients
  choose their names under `base_domain`.
- **`coord_pubkey` / `coord_pubkey_file`** — required. The coordinator's public
  grant key: inline (`calabi-coord pubkey` prints it), or the file the
  coordinator writes. If the file does not exist yet, the edge waits for it.
  From the environment: `CALABI_EDGE_COORD_PUBKEY` /
  `CALABI_EDGE_COORD_PUBKEY_FILE`.
- **The certificate.** Without `tunnel.control_cert_pem`/`control_key_pem`, the edge makes a
  self-signed certificate on its first start and keeps it in `state.dir`
  (`control.crt`, `control.key`). `./calabi-edge -config edge.yaml -fingerprint`
  prints its fingerprint. Clients get the fingerprint from the coordinator.
  Without a `state.dir`, the edge makes a new certificate at every start and
  warns.
- **TCP and UDP tunnels** get a public port from 20000–20999, or the one the
  client asks for (`--remote-port`, `remote_port:`). Open that port too.
- **Reloading.** `tunnel.base_domain` can be changed while the edge runs (edit
  the file). Every other field needs a restart; an edit to one while it runs is
  refused and logged.
- **One address, one port each.** `public.host` says where this node can be
  reached; every port is named by the service that listens on it. What clients
  dial is composed from the two, so no port is written twice.
- **Settings with two sources** are compared, and a file that answers
  differently in the two is refused, naming both: on a node with a control
  plane, `region` and `edge_node_id` against that node's own certificate, which
  is where the control plane reads them from.
- **Older spellings**, if you are upgrading. Every setting that moved still
  loads from where it was: the listener blocks `control:`, `http:`,
  `https:` and `sni:` as the ports `control_port`, `http_port`, `https_port`
  and `sni_port`, `public.addr` as `public.host` (its port has to match the
  control listener's), `base_domain` and `coord_pubkey` from under `http:` and
  `relay:`, `node_id` as `node_label`, the whole `relay:` block as `mesh:`. The
  role names `edge` and `relay` still mean `tunnel` and `mesh`. A
  file that spells one setting both ways with different values is refused,
  naming the one to keep. `accepted_tokens` was removed in 1.13: an empty list
  is ignored, and a list of tokens is refused.

### Every setting

Three groups: what both services use, what only tunnels use, and what only the
mesh relay uses. A node running `role: mesh` can leave out the whole `tunnel:`
block; one running `role: tunnel` can leave out `mesh:`.

The **for** column says who a setting is for. **calabi.net** marks the ones the
hosted service uses: a server you run reads none of them, and you can skip those
rows entirely. Everything else is either for any node, or only for a server of
your own.

**This node — read by both services, or by neither**

| setting | for | default | what it does |
|---|---|---|---|
| `node_label` | any node | `edge-dev-1` | This node's name for people (`lax-1`, `sgp-01`). It reaches your clients, the logs and every usage record |
| `region` | any node | `local` | Which region this node is in. Also gives the relay its region code, `self-<region>` |
| `mode` | any node | `platform` | Whose per-tunnel security policy the edge trusts: `standalone` — a server you run — the client's, `platform` the control plane's |
| `role` | any node | `tunnel` | Which of the two services this node provides: `tunnel`, `mesh`, or `both` |
| `coord_pubkey` | any node | — | Your coordinator's public grant key, base64. `calabi-coord pubkey` prints it |
| `coord_pubkey_file` | any node | — | The same key read from a file. The edge waits for it to appear |
| `public.host` | any node | — | Where this node is reached from outside it, a name or IP with no port — clients reach its tunnels here and devices reach its relay. **Required on a node that serves tunnels** |
| `admin.addr` | any node | `:9101` | `/healthz`, `/readyz`, `/metrics`. Keep it off the public internet |
| `state.dir` | any node | — | Where small things survive a restart: the subdomain counter and the self-signed certificates |
| `multi_region.*` | calabi.net | `mode: cluster` | The hosted platform's control-plane connection: `mode: bff-edge`, `bff_edge_addr`, `client_cert`, `client_key`, `ca`, `server_name` |
| `log.level` / `log.format` | any node | `info` / `text` | `debug`/`info`/`warn`/`error`, and `text`/`json` |

**`tunnel:` — read only by the tunnel service**

| setting | for | default | what it does |
|---|---|---|---|
| `base_domain` | any node | `localtest.me` | The wildcard domain this node serves: tunnels become `<name>.<base_domain>` |
| `control_port` | any node | `7443` | Where the `calabi` client connects |
| `control_cert_pem` / `control_key_pem` | any node | — | That listener's certificate. Left out, the edge makes a self-signed one in `state.dir`. Re-read when the files change |
| `http_port` | any node | `8080` | Visitors to HTTP tunnels |
| `https_port` | any node | `8443` | Visitors to HTTPS tunnels, with TLS terminated here. `0` turns HTTPS off |
| `https_self_signed` | your server | `false` | Fall back to a self-signed certificate when there is no real one. **Development only** |
| `sni_port` | any node | — | TLS passed straight through to the client without being decrypted here. Leave it out to turn it off |
| `peer_forward.forward_addr` | calabi.net | — | Where this edge accepts visitor traffic relayed by its neighbours. **An internal address, never the public one** |
| `peer_forward.advertise_addr` | calabi.net | — | The internal `host:port` its neighbours dial to reach that. Both must be set |

**`mesh:` — read only by the mesh relay**

| setting | for | default | what it does |
|---|---|---|---|
| `derp_port` | any node | `3340` | Where devices reach the relay |
| `stun_port` | any node | `3478` | The STUN responder devices measure to pick their nearest relay. `0` turns it off |
| `label` | any node | the node's `region` | The region name this relay advertises, as `self-<label>`. Set it only when one region has two relays |
| `kind` | any node | `self` | `self` for a relay of your own, `platform` for one of ours |
| `require_auth` | any node | `false` | Refuse devices without a valid grant. Always on for a `standalone` node |

**Settings that are refused.** The edge stopped reaching the control plane
directly, so `identity:`, `quota:`, `config_svc:`, `nats:`, `tunnel.addr` and
`cert.addr` no longer do anything. Neither do `presence.interval_seconds` and
`cert.refresh_seconds`, removed in 2.0.0: both had a default, and no deployed
config had ever set either. Nor does `edge_class`, which the hosted platform now
decides for itself — a node does not get to choose which paying plans are routed
to it. Nor `org_id` (or its older spelling `cert.org_id`): a node's organization
comes from its own certificate, and a node of ours serves every organization
rather than naming one. A file that still has any of them does not start, and
says which it is — rather than starting and quietly not doing what the file
describes. The one older spelling that is refused rather than read is a
top-level `mesh:` block carrying `forward_addr` / `advertise_addr`: that was
edge-to-edge forwarding of tunnel traffic, `mesh:` now configures the relay, and
reading either as the other would be worse than saying so.

**From the environment**, for a relay that needs no file at all:
`CALABI_EDGE_MODE`, `CALABI_EDGE_ROLE`, `CALABI_EDGE_ADMIN_ADDR`,
`CALABI_EDGE_PUBLIC_HOST`, `CALABI_EDGE_COORD_PUBKEY`,
`CALABI_EDGE_COORD_PUBKEY_FILE`, and
`CALABI_EDGE_RELAY_` + `KIND`, `LABEL`, `DERP_PORT`, `STUN_PORT`,
`REQUIRE_AUTH`, `COORD_PUBKEY`.

### HTTPS

With `base_domain` set and no certificate of its own for it, the edge serves
HTTPS on `tunnel.https_port` with a self-signed wildcard certificate it makes in
`state.dir` (`edge-https.crt`). Browsers show a warning unless you import it. A
self-hosted edge does not get Let's Encrypt certificates automatically yet.

### A relay on its own

To add a relay in another place — closer to some of your devices — run the edge
with `role: mesh`. It needs no config file:

```bash
CALABI_EDGE_MODE=standalone CALABI_EDGE_ROLE=mesh \
CALABI_EDGE_RELAY_LABEL=tokyo CALABI_EDGE_COORD_PUBKEY=<calabi-coord pubkey> \
./calabi-edge
```

It listens on 3340/tcp and 3478/udp and serves only devices with your
coordinator's grants. Add it to the coordinator's `CALABI_COORD_DERP_MAP_FILE`,
or register it through the admin API. Each device measures the relays and uses
the closest.

---

## Invites and devices

The admin commands talk to the running coordinator, with the same environment
(or `--admin` and `--token`):

```bash
./calabi-coord invite --note "Alice's phone"
```

It prints a `calabi://join?…` link, a QR code, and the same as a
`calabi join "…"` command line.

- By default an invite admits **one device**, within **24 hours**. `--uses 5`,
  `--reusable`, `--expires 72h` and `--no-expiry` change that.
- `--tag tag:phone` gives every device it admits that ACL tag.
- The link carries the key, and — for a self-signed coordinator certificate —
  its fingerprint. Send it only to the person it is for.

```bash
./calabi-coord authkey create --reusable --no-expiry --tag tag:server   # a key without the link
./calabi-coord authkey list
./calabi-coord authkey revoke 3            # no new devices join with it

./calabi-coord device list
./calabi-coord device disable 5            # the ID column; `enable 5` undoes it
./calabi-coord device delete 5
./calabi-coord device approve 5            # when the network requires approval
```

- **To remove a device, disable or delete it.** It leaves the mesh at once, and
  its tunnels stop within the hour ([why](#what-is-a-grant)). A deleted device
  needs a new invite to come back.
- **Revoking a key** stops new devices from joining with it. Devices it already
  admitted stay ([why](#why-does-revoking-a-key-not-remove-its-devices)).
- The coordinator stores only a hash of each key, so a key is shown once, when
  it is made.

---

## Coordinator and edge on different machines

- **On the coordinator:** `CALABI_COORD_EDGE_ADDR` (the edge's public address)
  and `CALABI_COORD_EDGE_PIN` (`calabi-edge -config edge.yaml -fingerprint` on
  the edge prints it). For an edge with a publicly trusted certificate, set
  `CALABI_COORD_EDGE_TRUST=system` instead. When you replace the edge's
  certificate, update the pin.
- **On the edge:** the coordinator's public key inline:
  `coord_pubkey: <what calabi-coord pubkey prints>`.
- **The relay** the coordinator names (`CALABI_COORD_DERP_ADDR`) is an edge that
  runs `role: both` or `role: mesh`.

---

## Joining

On a computer:

```bash
calabi join "calabi://join?…"
```

- If the client's daemon is running, it joins and restarts as your server's
  device. Otherwise the join is saved and the daemon started
  (`--no-start-daemon` skips starting it).
- `--name` sets the device's name, `--pin` gives the coordinator's fingerprint
  for an invite without one, and `--replace` moves the device from another
  server to this one.
- Signed in to calabi.net, it asks you to sign out first (`calabi logout`).
- With a calabi service installed (the desktop app's, or one from
  `calabi daemon install`), `calabi join` does not reach the service and starts
  nothing. Run `calabi daemon` to use the join, or connect the service from its
  own console ([why](#why-does-calabi-join-not-reach-my-installed-service)).

In the client's console at `http://127.0.0.1:7400` (the desktop app's window):
**Connect to a self-hosted server**, then paste the link, or type the
coordinator's address and a key. On a phone: the Calabi app → **Connect to a
self-hosted server** → scan the invite's code.

**The coordinator's certificate** is checked before the key is sent: with the
fingerprint in the invite, with the system's trusted roots, or — when neither
applies — by showing you the fingerprint to compare with
`calabi-coord fingerprint`. A join that stops at this step leaves the invite
unused.

**Servers and fleets.** A machine that should join on its own — a server, or
many machines built from one image — gets a config file instead of an invite:

```yaml
# calabi.yaml
server:
  coord: server.example.com:7012
  trust: pin
  pins: ["sha256:…"]          # calabi-coord fingerprint
  auth_key: ck_…              # calabi-coord authkey create --reusable --tag tag:server
  name: build-01
# mesh:
#   enabled: true             # also join the mesh; tunnels work either way
tunnels: []
```

```bash
calabi daemon install --config calabi.yaml    # a boot-start service; then: calabi daemon start|stop|status
```

The key is used for the first join only. After that the daemon reconnects with
its device key; it keeps which device it is in `mesh-reauth.json` in its data
directory. The file holds the key in plain text, so make it readable only by the
service. [`docs/examples/calabi.yaml`](examples/calabi.yaml) is an annotated
example.

---

## Tunnels

`calabi http|tcp|udp|sni` open one tunnel each and stay in the foreground:

```bash
calabi http 8080                         # → https://u000001.tunnels.example.com
calabi http 8080 --domain app.tunnels.example.com
calabi tcp  22   --remote-port 20022
calabi udp  53
```

They run as the device this client joined as; nothing else needs setting. On a
client that has not joined, they say so. `CALABI_DAEMON_CONFIG=calabi.yaml`
makes them run as the device a config file names instead.

### Per-tunnel security policy

Your edge applies each tunnel's access controls:

- **IP allow and deny lists**, on every tunnel type;
- on HTTP tunnels: **Basic auth**, **connection rate limits**, **request-header
  rewrite** and **OAuth sign-in** (Google, GitHub).

```bash
calabi http 8080 --domain app.tunnels.example.com \
  --ip-allow 10.0.0.0/8 --ip-deny 1.2.3.4 \
  --basic-auth alice:s3cret --basic-auth bob:hunter2 \
  --security-file policy.json      # or a full {"security":{…}} blob
```

Basic-auth passwords are bcrypt-hashed on your machine before they are sent. The
command prints whether the edge applied the policy.

### The daemon

The daemon runs all of a device's tunnels in one process, reconnects on its own,
and serves the console. After `calabi join` it is running; `calabi daemon`
starts it. It keeps the tunnels you create in the console in its own
`calabi.yaml`, in its data directory.

Run with `--config calabi.yaml`, it takes its tunnels (and the server it joins)
from that file instead — see [Servers and fleets](#joining) and
[`docs/examples/calabi.yaml`](examples/calabi.yaml):

```yaml
tunnels:
  - name: app
    type: http
    local: 127.0.0.1:8080
    domain: app.tunnels.example.com
    security:
      ip_allow: ["10.0.0.0/8"]
      basic_auth: ["admin:s3cret"]   # bcrypt-hashed at load
  - name: ssh
    type: tcp
    local: 127.0.0.1:22
    remote_port: 20022
```

**As a service.** `calabi daemon install --config …` registers a boot-start
service (Windows service, systemd, launchd) that restarts after a crash.

- The service writes its log next to the `calabi` binary.
- To change `--config`, run `calabi daemon uninstall`, then `install` again.
- On a self-hosted device, `daemon install` needs `--config`. The desktop app's
  service joins from its own console.

### The local web console (`:7400`)

While the daemon runs, **http://127.0.0.1:7400** shows:

- the tunnels with their traffic, and creates, edits and deletes them, security
  policy included (editing one re-registers only that tunnel);
- a **request inspector** (a log per connection, HTTP requests and responses);
- the daemon's logs;
- your server: every device's tunnels, this month's traffic, and
  **Settings → Self-hosted server** — the coordinator, the edge this device's
  tunnels run on, and the mesh switch.

A one-off `calabi http 8080` serves only a plain status page, on the same port
or the next free one.

**From other machines.** To reach the console from elsewhere, bind it beyond
loopback with `CALABI_STATUS_ADDR`. Visitors then enter its unlock secret first:
the daemon prints it at startup and keeps it in `console-secret` in its data
directory, or takes yours from `CALABI_STATUS_SECRET`. The console is plain HTTP;
across a network you don't trust, put it behind an SSH tunnel or an HTTPS proxy.

**Editing `calabi.yaml` by hand.** Console edits rewrite the file: values stay,
comments do not, and a managed-by header is added. For a file you keep under
version control, edit it and restart the daemon instead.

---

## The mesh

The mesh joins your devices into one private WireGuard network. Each device gets
a stable `100.64.0.0/10` address that stays the same on any network. Devices
connect directly when NAT allows, and through the edge's relay when it does not.

**On and off.** A device that joins is on the mesh. Turn it off in the console
(**Settings → Self-hosted server**) or with `calabi mesh down`; `calabi mesh up`
turns it back on. Off, the device has no mesh interface and the other devices do
not see it. It stays joined, its tunnels keep running, and the setting survives
a restart.

**Requirements.** Run the daemon as a service, or as root / Administrator: the
mesh creates a network interface. On Windows, `wintun.dll` is built into the
binary. The device's WireGuard key is made on the device and kept there
(`key_file:` sets where), so the device keeps its identity and its address.

Mesh settings in a daemon's `calabi.yaml` — the console edits the same ones.
Which server the device belongs to is in `server:`, not here: the device needs
it whether or not the mesh runs.

```yaml
server:
  coord: server.example.com:7012
  pins: ["sha256:…"]
  name: laptop
mesh:
  enabled: true
  advertise_routes: ["192.168.1.0/24"]   # share a LAN
  advertise_exit_node: true              # offer to be an exit device
  exit_node: home-server                 # send this device's traffic out through a peer
```

`calabi mesh up --coord … --pin … --auth-key …` runs only the mesh, in the
foreground, without the daemon — for a quick test. It exits when its connection
to the coordinator ends. `calabi mesh status` asks the running daemon.

### ACLs

Without `CALABI_COORD_POLICY_FILE`, every device in a meshnet reaches every
other. With it, a JSON file of groups and rules decides who reaches whom, on
which ports.

- The coordinator reloads the file when it changes.
- A file that is broken when the coordinator starts denies all traffic, and the
  coordinator logs why. Fix the file; no restart is needed.
- A broken edit while it runs is logged, and the previous policy stays.

An ACL saved for a meshnet through the admin API
(`PUT /admin/meshnets/<id>/acl` on `CALABI_COORD_MESH_ADMIN_ADDR`) replaces the
file, or allow-all, for that meshnet. There is no call to remove it. Without a
database it lasts until the coordinator restarts.

### Subnet routers and exit devices

A **subnet router** shares a LAN behind it with the mesh. An **exit device**
carries another device's internet traffic.

| | Linux | Windows, macOS |
|---|---|---|
| Share a subnet, or be an exit device | yes — forwarding and NAT are set up for you | only from `calabi.yaml` (`advertise_routes:`, `advertise_exit_node:`), with forwarding and NAT set up by you; the console does not offer it |
| Reach a subnet another device shares | yes | yes |
| Use an exit device | yes | yes |

---

## Phones and the desktop console

**Connecting.** On the sign-in page of the Android app, or of the client's
console (`:7400`, the desktop app's window): **Connect to a self-hosted server**,
then an invite (link or QR code), or the coordinator's address and a key.

- The phone joins the mesh. It does not run tunnels.
- The console's daemon restarts as your server's device, on the same port.
- These do not switch: a daemon run with `--config` (it keeps the server its file
  names), a daemon with `CALABI_MODE` set, and a service installed with an API
  key.

**When the coordinator's certificate changes**, the app stops connecting and
shows the fingerprint it trusts beside the one presented now. Trust the new one
to reconnect; that applies to this certificate only. Until then the app keeps
retrying with the old one, so putting the old certificate back brings devices
back by themselves. A new edge certificate needs nothing from anyone.

**Devices, tunnels and traffic.** Both apps list the network's devices. With a
database on the coordinator they also show tunnels and this month's traffic:

- **Tunnels** — the ones the desktop daemons report: name, type, public address,
  local address, whether it is up, and bytes. Daemons report every five minutes
  and whenever the list changes, with the mesh on or off. Tunnels run by
  `calabi http` are not listed.
- **Traffic** — tunnel traffic plus relayed mesh traffic
  ([how it is counted](#how-is-traffic-counted)). Days and months follow the
  viewer's time zone. The coordinator keeps 92 days of tunnel traffic.
- **Without a database**, the tunnel list is kept in memory (the daemons fill it
  again within minutes of a restart) and there is no traffic record. The apps
  say so.

**Leaving.** *Disconnect and forget this server* in the console, *Leave this
server* on the phone:

- The coordinator marks the device as left. It needs a new invite to come back.
- The app forgets the server.
- The console also deletes its `calabi.yaml` and the tunnels in it (it shows how
  many first), then goes back to the calabi.net sign-in page.
- The device key stays: joining the same coordinator again is the same device.

---

## Only on calabi.net

These need a calabi.net account. The client has the commands, but they do not
work with a self-hosted server:

- `calabi login`, `logout`, `org`, `certs`, `domains`, `clients`;
- managed edges in several regions, and choosing among them;
- accounts, organizations, billing, and the web console;
- automatic Let's Encrypt certificates for tunnel domains.

---

## Production notes

- **Back up the coordinator**: the database, `coord-grant.key` and `coord-tls/`.
  Without them, every device joins again with a new invite.
- Keep the edge's `state.dir`: the subdomain counter and its certificates are
  there.
- Keep the admin addresses on a private interface: the coordinator's `:9122` and
  its mesh admin API, the edge's `:9101`.
- Set `CALABI_ENV=production` on the coordinator and the edge. Each then refuses
  to start with an open default.
- Limit the edge's total connections with `EDGE_GLOBAL_MAX_CONNS` and
  `EDGE_GLOBAL_ACCEPT_RATE_PER_SEC`.
- Run the device daemons as services (`calabi daemon install --config …`) so
  they start at boot.

---

## Monitoring

The coordinator and the edge each serve `/metrics` and `/healthz` on their admin
address — `:9122` and `:9101` in the bundle, both on `127.0.0.1`.

[`deploy/server/monitoring`](../deploy/server/monitoring) is a ready Prometheus
setup for them: a scrape config, three alerts, and tests that prove the alerts
fire. From `deploy/server`:

```bash
docker compose -f docker-compose.yml -f monitoring/docker-compose.monitoring.yml up -d
ssh -L 9090:127.0.0.1:9090 you@your-server   # then open http://127.0.0.1:9090
```

The three alerts:

| Alert | Fires when |
| --- | --- |
| `CalabiTargetDown` | Either program stopped answering for 3 minutes. |
| `CalabiEdgeFailingVisitors` | The edge has been failing or shedding visitor traffic for 10 minutes. |
| `CalabiCoordRPCErrors` | The coordinator has been failing device RPCs for 10 minutes. |

They stay silent for your own access rules refusing visitors, and for strangers
scanning your address — both are normal
([why](#why-doesnt-the-edge-alert-count-every-failed-request)). A tunnel's
upstream being down is also ignored by default;
[the README](../deploy/server/monitoring/README.md) says how to include it if
you run those services yourself.

Nothing in it reaches calabi.net.

---

## Upgrading to 2.0

The edge's config file changed in 2.0. A server that has been running since
1.14 will not start on the new edge until its config catches up.

**If you run the Docker bundle**, take the new `docker-compose.yml` along with
the new image. That file writes the edge's config, and the version of it shipped
before 2.0 wrote one the new edge refuses: it had no `public:` block. Your
`.env` needs nothing new — the value comes from `CALABI_PUBLIC_HOST`, which you
already set.

**If you wrote your own edge config**, two things can stop it.

- **`public.host` is required** on a node that serves tunnels. It is the host
  devices dial and the name the control certificate is issued for. It used to be
  optional, falling back to the listener's bind address — a usable dial string
  only on the one machine that is also the device. A relay-only node does not
  need it.
- **Settings that had stopped doing anything are refused**, rather than skipped:
  the `identity:`, `quota:`, `config_svc:` and `nats:` blocks, `tunnel.addr`,
  `cert.addr`, `presence.interval_seconds`, `cert.refresh_seconds`,
  `edge_class` and `org_id`. Delete them. The edge names the offending line at
  startup.

Everything else migrates. The file is now grouped by service — `tunnel:` for
what only tunnels read, `mesh:` (formerly `relay:`) for the relay, the top level
for what both use — and each listener names a port rather than an address, but
every old spelling still loads from where it was:

| You wrote | It now reads as |
|---|---|
| `control: { addr: ":7443" }` | `tunnel.control_port: 7443` |
| `control: { cert_pem: … }` | `tunnel.control_cert_pem: …` |
| `http: { addr: ":80" }` | `tunnel.http_port: 80` |
| `https: { self_signed: true }` | `tunnel.https_self_signed: true` |
| `http: { base_domain: … }` | `tunnel.base_domain: …` |
| `relay:` | `mesh:` |
| `public: { addr: "host:7443" }` | `public: { host: "host" }` |

Two exceptions to "it migrates". A `public.addr` whose port disagrees with the
control listener's is refused, naming both — that file would otherwise come up
unreachable. And a top-level `peer_forward:` block spelled `mesh:` (edge-to-edge
forwarding of tunnel traffic, which was never about the mesh) is refused rather
than read as relay settings; it is `tunnel.peer_forward:` now.

The daemon's own config file is renamed from `tunnels.yaml` to `calabi.yaml` in
this release, and the coordinator moves from `mesh:` to a top-level `server:`
block. That one needs nothing from you: an old file still loads, and is
rewritten the next time anything saves it.

---

## Upgrading from 1.12 or earlier

In 1.13 the coordinator became every device's identity, for tunnels as well as
the mesh.

- **The edge takes no tokens.** It needs `mode: standalone` and the
  coordinator's public key, and admits devices with the coordinator's grants. A
  config that still lists `accepted_tokens` is refused at start.
- **The daemon config no longer names the edge.** `server: <url>`, `token`,
  `token_env`, `insecure`, `ca_file`, `trust` and `pins` at the top level are
  refused in a file you wrote, and dropped with a warning from the console's own
  file. Join the coordinator (`calabi join`, or a `server:` block) and the edge
  comes from it. (`server:` opening a BLOCK is the coordinator, and is read
  normally — only the old one-line form is refused.)
- **The one-shot commands** no longer read `CALABI_SERVER`, `CALABI_TOKEN`,
  `CALABI_EDGE_PIN` or `CALABI_EDGE_TRUST` on a self-hosted device.
- **A self-hosted relay always checks grants.** Give it the coordinator's key.
- **The coordinator serves TLS.** Without certificate files it used to serve
  plaintext; now it makes a self-signed certificate. Pin its fingerprint on the
  devices, or set `CALABI_COORD_TLS=off`.
- **`calabi mesh down` lasts across restarts** on a self-hosted device;
  `calabi mesh up` with no arguments turns the mesh back on.

---

## Questions

### What is a grant?

A grant is what a device shows the edge to get in. The coordinator signs one for
each device: the device's key, its network, and an expiry an hour ahead. The
edge admits a device that shows a valid grant and proves it holds the key the
grant names — for tunnels and the relay alike.

- A device asks the coordinator for a fresh grant before each connection to the
  edge, and renews it when a third of the hour is left.
- The edge checks grants by itself; it does not ask the coordinator. So when you
  disable or delete a device, the device can no longer renew, and the edge ends
  its tunnels when the grant it holds runs out — within the hour.

### How do devices trust the edge's certificate?

Devices get the edge's address and fingerprint from the coordinator, and pin
that fingerprint.

Without `CALABI_COORD_EDGE_PIN`, the coordinator reads the fingerprint from the
edge itself: every few seconds until it has one, then once a minute. A new edge
certificate therefore reaches every device with nobody confirming it, and the
coordinator logs the change. Until it has read one, it gives devices no edge.

Reading it this way is only safe when nothing between the coordinator and the
edge can be tampered with — the same machine, or a compose network. Across the
internet, set `CALABI_COORD_EDGE_PIN`.

### Why is the coordinator's certificate checked before anything else?

The invite key is a secret, and it is sent to the coordinator when a device
joins. The app settles which certificate it trusts first, so the key only goes
to your coordinator, and the key is spent last.

The client also carries a CA built in; that one is calabi.net's, and it is never
used for your coordinator. For your own CA, set `ca_file:`.

### Why does revoking a key not remove its devices?

A key is used only to join. After joining, a device reconnects by proving it
holds its own device key, so it no longer needs the key that admitted it. To
remove a device, disable or delete it.

### Why does `calabi join` not reach my installed service?

The service is a separate client with its own data directory, not your user's.
`calabi join` saves the join for the client you ran it from. Connect the service from its own console (the desktop app's
window, or `http://127.0.0.1:7400`), or run `calabi daemon` to use the join from
your terminal.

### Can the coordinator or the relay see my traffic?

No. Each device makes its WireGuard key itself; the coordinator never has a
private key. Mesh traffic goes directly between devices, or through the relay,
which forwards encrypted packets by device key. The relay has no code that could
decrypt them: `pkg/relay` contains no edge or control-plane code, and a
dependency test keeps it that way.

### What does a device connect to?

Your coordinator, and the edge the coordinator names. There are no analytics.
The client has one fixed address outside your network: the signed update
manifest on `download.calabi.net`, which only a daemon signed in to calabi.net
checks. A self-hosted daemon does not.

### How is traffic counted?

- Tunnel traffic, per tunnel, as the daemon reports it.
- Relayed mesh traffic, once, on the sending side.
- Direct connections between devices do not pass through your server and are
  not counted.

A device counts as up for its tunnels while it is on the mesh, or while its
reports keep coming.

### Is the self-hosted mesh the same as calabi.net's?

Yes. The mesh is the same code: your coordinator has its own keys, ACLs, relays
and devices. calabi.net adds accounts, organizations and metering around it.

### Can a device be on my server and on calabi.net?

One at a time. Signed in to calabi.net, the client asks you to sign out before
it joins your server. `calabi join --replace` moves a device from one server to
another.

### Why doesn't the edge alert count every failed request?

Because most failed requests are not your server failing.

The edge records an `outcome` for every visitor request, and they fall into
three groups. Only the first is a fault:

- **Your server** — `internal_error`, `replay_head_failed`, and the `global_*`
  pair, which mean the edge is saturated and dropping traffic.
- **Your upstream** — `open_upstream_failed`: whatever the tunnel points at
  refused the connection. Yours to fix if you run it, which is why the README
  says how to include it.
- **Your rules** — `rate_limited`, `ip_denied`, `conn_capped`, `daily_capped`,
  `auth_required`, `oauth_redirect`. The access control you configured, doing
  its job.

`no_tunnel` and `sniff_failed` are left out as well: a public address is
scanned continuously by strangers, and on a quiet server those can easily
outnumber real requests. An alert that counted them would fire every day and
tell you nothing.

You can see all of them at once:

```promql
sum by (proxy_type, outcome) (rate(calabi_edge_visitor_requests_total[5m]))
```

---

## License & contributing

Open source under the terms in [LICENSE](../LICENSE) (see also `NOTICE`). Issues
and patches to the edge, the client, the coordinator and the local console are
welcome.
