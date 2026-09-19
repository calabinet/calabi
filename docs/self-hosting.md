# Calabi — self-hosting

**English** · [中文](self-hosting.zh-CN.md)

Calabi's **data plane is open source** — three binaries. Two of them are your
server, and the third runs on each of your devices:

- `calabi-coord`, the coordinator: where devices join, get their `100.64.x.x`
  address and find each other, and where the phone app and each console see the
  network's devices, tunnels and traffic;
- `calabi-edge`: takes public traffic for your **tunnels**, and relays **mesh**
  traffic between devices that cannot reach each other directly;
- `calabi`, the client: serves tunnels and joins the private WireGuard mesh.

The coordinator is every device's identity. A device joins it once, with an
invite; from then on the coordinator tells it where the edge is, and signs the
grant the edge lets it in with. So the same device has tunnels and the mesh, and
the mesh can be switched off on it without losing the tunnels.

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

The **control plane** — accounts, organizations, billing, the managed global edge
fleet — is a separate, closed, hosted product. These three binaries never phone
home, need no account, and run entirely on infrastructure you own. The Android
app in `apps/client-android` and the client's own console join your server too;
see [Phones and the desktop console](#phones-and-the-desktop-console).

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
- [Tunnels](#tunnels) — [policy](#per-tunnel-security-policy), [the daemon](#the-daemon), [the console](#the-local-web-console-7400)
- [The mesh](#the-mesh) — [ACLs](#acls), [subnet routers and exit devices](#subnet-routers-and-exit-devices)
- [Phones and the desktop console](#phones-and-the-desktop-console)

**Then**

- [What self-hosting does *not* give you](#what-self-hosting-does-not-give-you)
- [Production notes](#production-notes)
- [Upgrading from 1.12 or earlier](#upgrading-from-112-or-earlier)
- [License & contributing](#license--contributing)

---

## Quick start: your server in Docker

On a Linux machine with a public address and Docker Compose (or `podman compose`), the
bundle in [`deploy/server`](../deploy/server) runs the coordinator and the edge
together from one `.env`:

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

The phone app scans the invite's QR code instead. The bundle's
[README](../deploy/server/README.md) covers devices, updates and backups; the
rest of this page is what it does underneath, and every setting.

---

## Get the binaries

Every release has all three for Linux (amd64, arm64, armv7), macOS and Windows on
the [releases page](https://github.com/calabinet/calabi/releases), with a
`build-manifest.json` that rebuilds them from this source and compares.
`calabi-edge` and `calabi-coord` are also docker images, `calabinet/calabi-edge`
and `calabinet/calabi-coord` (amd64, arm64).

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

The server, the edge and the clients should run the same release: devices need
1.13 or later to join, and everything described here is 1.13.

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
| `CALABI_COORD_PUBLIC_ADDR` | the address devices dial, `host:port` — what invite links carry |
| `CALABI_COORD_DB_DSN` | where state lives. `sqlite:./coord.db` for a file, or a `postgres://…` URL. **Unset = in memory** — see below |
| `CALABI_COORD_MESH_ADMIN_ADDR` / `_TOKEN` | the admin HTTP API, which `calabi-coord invite`, `authkey` and `device` use. Bind it to a private address. **A tokenless admin surface is refused at startup** |
| `CALABI_COORD_ADMIN_ADDR` | health + metrics. Default `:9122`; keep it private |
| `CALABI_COORD_EDGE_ADDR` | the edge devices use for tunnels, `host:port` of its control listener |
| `CALABI_COORD_EDGE_PIN` | that edge's certificate fingerprint (`calabi-edge -fingerprint`). Unset: the coordinator reads it from the edge — see below |
| `CALABI_COORD_EDGE_TRUST` | `system` for an edge with a publicly trusted certificate: no fingerprint is sent, devices check it against their system roots |
| `CALABI_COORD_EDGE_PROBE_ADDR` | where the coordinator itself reaches the edge to read its certificate, when that differs from `EDGE_ADDR` (`127.0.0.1:7443` next to each other, `edge:7443` in a compose network) |
| `CALABI_COORD_RELAY_GRANT_KEY_FILE` | the key the coordinator signs grants with. Default `./coord-grant.key`, created on first start |
| `CALABI_COORD_GRANT_PUBKEY_FILE` | write the public half of that key to this file at every start, for an edge that reads it |
| `CALABI_COORD_DERP_ADDR` | one relay, the simple case: `host:port` |
| `CALABI_COORD_DERP_STUN_PORT` | that relay's STUN port. Without it the region cannot be measured, so nobody homes there |
| `CALABI_COORD_DERP_HOME_REGION` | the region name for `CALABI_COORD_DERP_ADDR` (default `default`); with a map file that sets no `home_region`, the region new devices start on |
| `CALABI_COORD_DERP_MAP_FILE` | several relays instead: a JSON directory (see `apps/calabi-coord/examples/derp-map.example.json`) |
| `CALABI_COORD_AUTHKEYS_FILE` | your own permanent auth keys, optional. JSON: `{"key": {"meshnet": 1, "tags": ["tag:laptop"]}}` |
| `CALABI_COORD_POLICY_FILE` | the ACL file. Unset = every device in a meshnet reaches every other — see [ACLs](#acls) |
| `CALABI_COORD_NODE_QUOTA` | cap on devices per meshnet. Unset or `0` = unlimited |
| `CALABI_COORD_TLS_CERT_FILE` / `_KEY_FILE` | serve gRPC with this certificate. Both or neither. Neither = a self-signed certificate — see [its certificate](#the-coordinators-certificate) |
| `CALABI_COORD_TLS_DIR` | where the self-signed certificate is kept. Default `./coord-tls` |
| `CALABI_COORD_TLS` | `off` serves plaintext |

**Grants.** The coordinator is the one thing that says who a device is. It signs
each device a grant — the device's key, its network, an expiry an hour out — and
the edge accepts a device that shows a grant and proves it holds the key the
grant names, for tunnels and relay alike. Devices renew theirs before it runs
out. `calabi-coord pubkey` prints the public half of the key; give it to the edge,
or let the coordinator write it to `CALABI_COORD_GRANT_PUBKEY_FILE` where the
edge reads it. **Keep `coord-grant.key`**: a new one is a new public key, and an
edge holding the old one turns every device away.

**The edge it names.** Devices ask the coordinator for the edge and its
fingerprint, and pin that. With no `CALABI_COORD_EDGE_PIN` the coordinator
connects to the edge and reads the certificate it presents — every few seconds
until it has read it once, then once a minute — so an edge that replaces its
certificate is followed without anyone confirming anything; it logs the change.
Until it has read one, it tells devices of no edge rather than letting them
check a self-signed certificate some other way. That reading is only right when
the path between the two cannot be tampered with — the same machine, a compose
network; otherwise give `CALABI_COORD_EDGE_PIN`.

A `meshnet` is one isolated network. Two keys mapping to different meshnet
numbers produce two networks on one coordinator that cannot see each other.

> **Give it a database.** With no `CALABI_COORD_DB_DSN` the coordinator keeps
> the device registry, the ACL document, declared services and the relay
> directory **in memory** — it says so at startup, and it means a restart
> empties the registry: every device joins again and gets a *different*
> `100.64.x.x` address. `CALABI_COORD_DB_DSN=sqlite:./coord.db` is enough; there
> is no Postgres requirement. A DSN that is set but unusable aborts startup
> rather than falling back to memory. With neither a key file nor a database the
> coordinator accepts a built-in key, `dev-meshnet-1-key`, into meshnet 1 — for
> a first try on your own machine.

> Set `CALABI_ENV=production` and the coordinator refuses to start on any
> fail-open fallback — most importantly the built-in key, which admits *any*
> caller into meshnet 1, so it needs a key file or a database. It also requires
> `CALABI_COORD_NODE_QUOTA` to be set (`0` for no cap). Do that on anything
> reachable from the internet.

### The coordinator's certificate

**Invite keys cross the connection to the coordinator**, so it serves TLS.
Without `CALABI_COORD_TLS_CERT_FILE`/`_KEY_FILE` it generates a self-signed
certificate on its first start and keeps it in `CALABI_COORD_TLS_DIR`. Keep that
directory: a new certificate has a new fingerprint, and every device that pinned
the old one stops connecting until someone confirms the new one on it.
`calabi-coord fingerprint` prints the fingerprint; invites carry it.

How a device checks the coordinator's certificate (`trust:` in its config,
`--trust` for `calabi mesh up`):

| trust | checks | set with |
|---|---|---|
| `pin` | the certificate's key against a fingerprint; host name not checked | the fingerprint in an invite, `pins:`, `--pin` |
| `system` | the operating system's trusted roots and the host name — a coordinator with a Let's Encrypt certificate | the default when an invite carries no fingerprint |
| `ca` | only your CA, and the host name | `ca_file:`, `--ca-file` |
| `plaintext` | nothing | `trust: plaintext`, `--trust plaintext` |

A connection to your coordinator never trusts the CA compiled into the client;
that one is calabi.net's. `CALABI_COORD_TLS=off` serves plaintext — for a network
you trust, or behind a proxy that terminates TLS. Invites for it need
`calabi-coord invite --allow-plaintext` and say so in the link; typing such a
coordinator's address into an app needs **No encryption** ticked.

---

## The edge

The edge reads a YAML file (`./calabi-edge -config edge.yaml`):

```yaml
mode: standalone             # belongs to your coordinator; required
role: both                   # tunnels and the mesh relay in one process
coord_pubkey_file: ./coord.pub   # the coordinator's grant key (or coord_pubkey: <base64>)
node_label: my-server        # this node's name in its logs
base_domain: tunnels.example.com  # HTTP tunnels become <name>.<base_domain>

control:
  addr: ":7443"              # devices connect here
  cert_pem: ""               # a certificate; empty = self-signed, kept in state.dir
  key_pem: ""

http:
  addr: ":80"                # visitors
https:
  addr: ":443"               # see HTTPS below

relay:
  derp_port: 3340            # the relay
  stun_port: 3478            # 0 disables the STUN responder
  label: my-server           # this relay's name in its logs

admin:
  addr: "127.0.0.1:9101"     # /healthz + /metrics — keep it private

state:
  dir: ./state               # the subdomain counter and the self-signed certificates
```

- **`mode: standalone`** — the edge belongs to a coordinator you run. It then
  accepts devices by that coordinator's grants and nothing else (no tokens, no
  control plane), applies the security policy each tunnel's client sends, and
  lets clients pick their own names under `base_domain`. An edge that serves
  tunnels without `mode: standalone` refuses to start.
- **`coord_pubkey` / `coord_pubkey_file`** — the coordinator's public grant
  key, inline (`calabi-coord pubkey` prints it) or in the file the coordinator
  writes. Required. With a file that does not exist yet, the edge waits for it —
  started next to the coordinator, it comes up a moment after it.
  `CALABI_EDGE_COORD_PUBKEY` / `CALABI_EDGE_COORD_PUBKEY_FILE` set them from the
  environment. (`relay.coord_pubkey` is the older spelling and must agree.)
- **The certificate.** Without `control.cert_pem`/`key_pem` the edge makes a
  self-signed certificate on its first start and keeps it in `state.dir`
  (`control.crt`, `control.key`); `./calabi-edge -config edge.yaml -fingerprint`
  prints its fingerprint. Devices get the fingerprint from the coordinator, so a
  replaced certificate is followed on its own. With no `state.dir` either, the
  edge makes a new certificate at every start and warns.
- **TCP and UDP tunnels** get a public port from 20000–20999, unless the client
  asks for another (`--remote-port`, `remote_port:`) — open that one too.
- **Hot reload.** `base_domain` can change while the edge runs (edit the file);
  every other field is read at start, and an edit to one is refused whole, with
  a log line.
- **Old keys.** `node_id` and `http.base_domain` are older spellings of
  `node_label` and `base_domain` and still load; both spellings with different
  values are refused. `accepted_tokens` is gone: an empty list is ignored, and a
  file that still lists tokens is refused — devices sign in with grants.

### HTTPS

With `base_domain` set and no certificate of its own for it, the edge serves
HTTPS on `https.addr` with a self-signed wildcard certificate it generates under
`state.dir` (`edge-https.crt`). Browsers warn unless it is imported. Automatic
Let's Encrypt certificates on a self-hosted edge are not there yet.

### A relay on its own

A relay somewhere else — closer to some of your devices — is the edge with
`role: relay`, and no config file is needed:

```bash
CALABI_EDGE_MODE=standalone CALABI_EDGE_ROLE=relay \
CALABI_EDGE_RELAY_LABEL=tokyo CALABI_EDGE_COORD_PUBKEY=<calabi-coord pubkey> \
./calabi-edge
```

It listens on 3340/tcp and 3478/udp, and serves only devices with a grant from
your coordinator. List it in the coordinator's `CALABI_COORD_DERP_MAP_FILE`, or
register it through the admin API; devices measure each relay over STUN and home
on the closest. The relay forwards ciphertext by device key and has no code path
that could decrypt it — that isolation is structural (`pkg/relay` carries no edge
or control-plane code, enforced by a dependency test).

---

## Invites and devices

The admin commands talk to the running coordinator's admin API, with the same
environment (or `--admin` and `--token`):

```bash
./calabi-coord invite --note "Alice's phone"
```

It prints a `calabi://join?…` link, a QR code, and the same as a
`calabi join "…"` command line. By default an invite admits **one device** and
admits new devices for **24 hours**: `--uses 5`, `--reusable`, `--expires 72h`
and `--no-expiry` change that, and `--tag tag:phone` stamps an ACL tag on every
device it admits. The link carries the coordinator's fingerprint when its
certificate is the self-signed one, and it carries the key: send it only to the
person it is for.

```bash
./calabi-coord authkey create --reusable --no-expiry --tag tag:server   # a key without the link
./calabi-coord authkey list
./calabi-coord authkey revoke 3            # stops new devices joining with it

./calabi-coord device list
./calabi-coord device disable 5            # the ID column; `enable 5` undoes it
./calabi-coord device delete 5
./calabi-coord device approve 5            # when the network requires approval
```

A key admits a device; it does not stay attached to it. Once joined, a device
comes back by proving it holds its own key, so revoking a key stops new devices
and removes none. **To remove a device, disable or delete it.** It leaves the
mesh at once; its tunnels stop when the grant it holds runs out, within the hour
(the edge checks grants offline and hears nothing from the coordinator). A
deleted device needs a new invite to come back. Only a hash of each key is
stored; the key itself is shown once, when it is made.

---

## Coordinator and edge on different machines

- The coordinator needs `CALABI_COORD_EDGE_ADDR` (the edge's public address)
  and, since it should not trust what it reads over the internet,
  `CALABI_COORD_EDGE_PIN` — `calabi-edge -config edge.yaml -fingerprint` on the
  edge prints it. An edge with a publicly trusted certificate takes
  `CALABI_COORD_EDGE_TRUST=system` instead. When you replace the edge's
  certificate, update the pin.
- The edge needs the coordinator's public key inline:
  `coord_pubkey: <calabi-coord pubkey>`.
- The relay the coordinator names (`CALABI_COORD_DERP_ADDR`) is whichever edge
  runs `role: both` or `role: relay`.

---

## Joining

On a computer:

```bash
calabi join "calabi://join?…"
```

If the client's daemon is running, it joins and starts again as your server's
device; otherwise the join is saved in the client's data directory and the
daemon started (`--no-start-daemon` skips that). `--name` sets the device's
name; `--pin` gives the coordinator's fingerprint for an invite that carries
none; `--replace` moves a device from one server to another. Signed in to
calabi.net, it asks you to `calabi logout` first.

On a computer with a calabi service installed (the desktop app's, or one from
`calabi daemon install`), that service is a separate client with its own data
directory: the join does not reach it, and `calabi join` starts nothing. Run
`calabi daemon` to use the join, or connect the service from its own console.

The same from the client's console at `http://127.0.0.1:7400` — the desktop
app's window: **Connect to a self-hosted server**, paste the link (or type the
coordinator's address and a key). On a phone: the Calabi app → **Connect to a
self-hosted server** → scan the invite's code.

**Certificates.** Before a key goes anywhere, the app settles how it checks the
coordinator: the fingerprint in the invite, a certificate the system trusts, or
— neither — the fingerprint the coordinator presents, shown for you to compare
with `calabi-coord fingerprint`. The key is spent last, so a join that stops
there spends nothing. The edge needs no such step: its fingerprint comes from
the coordinator.

**Servers and fleets.** A machine that should join on its own — a server, a
fleet built from one image — gets a config file instead of an invite:

```yaml
# tunnels.yaml
mesh:
  coord: server.example.com:7012
  trust: pin
  pins: ["sha256:…"]          # calabi-coord fingerprint
  auth_key: ck_…              # calabi-coord authkey create --reusable --tag tag:server
  name: build-01
  # enabled: true             # also join the mesh; tunnels work either way
tunnels: []
```

```bash
calabi daemon install --config tunnels.yaml    # a boot-start service; then: calabi daemon start|stop|status
```

The daemon joins with the key the first time, remembers which device it is
(`mesh-reauth.json` in its data directory), and comes back by proving its own
key from then on. `auth_key:` is read literally — keep the file mode tight.
[`docs/examples/tunnels.yaml`](examples/tunnels.yaml) is the annotated version.

---

## Tunnels

`calabi http|tcp|udp|sni` open one tunnel each and stay in the foreground:

```bash
calabi http 8080                         # → https://u000001.tunnels.example.com
calabi http 8080 --domain app.tunnels.example.com
calabi tcp  22   --remote-port 20022
calabi udp  53
```

They use the identity of the device this client joined as — the coordinator
names the edge and signs the grant — so there is nothing to set. A client that
has not joined says so. `CALABI_DAEMON_CONFIG=tunnels.yaml` makes them use the
device a config file names instead of the console's.

**How a device reaches the edge.** Before each connection it asks the
coordinator for the edge and a fresh grant, dials the edge pinned to the
fingerprint the coordinator gave, and answers the edge's challenge with its key.
The grant lasts an hour and is renewed with a third of it left; the edge ends a
session whose grant runs out unrenewed. That is how a disabled or deleted device
loses its tunnels.

**What the client reaches out to.** A device of your server dials your
coordinator and the edge it names, and nothing else. There are no analytics in
this tree, and the whole client carries one hard-coded non-local address: the
signed update manifest at `download.calabi.net`, which only the calabi.net daemon
polls; the self-hosted daemon is routed away before that code runs.

### Per-tunnel security policy

Every per-tunnel access control ships in this binary, and your edge applies all
of them: **IP allow/deny** (all tunnel types), and for HTTP **Basic auth**,
**connection rate limiting**, **request-header rewrite** and **OAuth
authentication** (Google / GitHub). Passwords are bcrypt-hashed **locally**
before they leave your machine:

```bash
calabi http 8080 --domain app.tunnels.example.com \
  --ip-allow 10.0.0.0/8 --ip-deny 1.2.3.4 \
  --basic-auth alice:s3cret --basic-auth bob:hunter2 \
  --security-file policy.json      # or a full {"security":{…}} blob
```

The edge's answer says whether it applied the policy, and the command prints it.

### The daemon

The daemon runs all of a device's tunnels in one process, reconnects on its
own, and serves the console. After `calabi join` it is running; `calabi daemon`
starts it. It keeps the tunnels you create in the console in its own
`tunnels.yaml`, in its data directory.

A daemon run with `--config tunnels.yaml` takes its tunnels (and the server it
joins) from that file instead; see [Servers and fleets](#joining) and
[`docs/examples/tunnels.yaml`](examples/tunnels.yaml):

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

> **Service notes.** `calabi daemon install --config …` registers a boot-start
> service (Windows service, systemd, launchd) that restarts on crash. A service
> has no per-user home, so it writes its log next to the `calabi` binary.
> Changing `--config` takes effect after `calabi daemon uninstall` + `install`
> again. In standalone mode `daemon install` without `--config` refuses: a
> service reads its own data directory, where your `calabi join` is not. The
> desktop app's service joins from its own console instead.

### The local web console (`:7400`)

While the daemon runs, **http://127.0.0.1:7400** shows:

- the tunnels with their traffic counters — and creates, edits and deletes them,
  security policy included (editing one re-registers just that tunnel);
- a **request inspector** (per-connection log, HTTP request/response capture);
- the daemon's logs;
- the server: every device's tunnels as the coordinator keeps them, this month's
  traffic, and **Settings → Self-hosted server**: the coordinator, the edge the
  device's tunnels run on, and the mesh switch.

A one-off `calabi http 8080` serves only a plain status page on the same port
(or the next free one).

If you bind the console beyond loopback (`CALABI_STATUS_ADDR`), visitors from
other machines must first enter its unlock secret: the daemon prints it at
startup and keeps it in `console-secret` in its data directory, or takes your own
from `CALABI_STATUS_SECRET`. It is plain HTTP — over a network you don't trust,
use an SSH tunnel or an HTTPS proxy.

> Console edits rewrite `tunnels.yaml` (values preserved, **comments not** — a
> managed-by header is added). If you keep a hand-written file under version
> control, prefer editing it and restarting the daemon.

---

## The mesh

Tunnels bring the public in. The mesh joins **your own** machines into one
private WireGuard network — stable `100.64.0.0/10` addresses that follow a
machine across networks, direct peer-to-peer paths where NAT allows one, and the
edge's relay where it doesn't. The coordinator never sees a private key or
plaintext; neither does the relay.

A device that joins is on the mesh. **Switch it off** — the console's
**Settings → Self-hosted server**, or `calabi mesh down` (`calabi mesh up` turns
it back on) — and the device leaves the mesh: no network interface, not a peer
on the others. It stays joined and its tunnels keep working; the switch
survives a restart.

The mesh needs a tun device and privileges: the daemon as a service, or run as
root / Administrator. On Windows `wintun.dll` is embedded in the binary. The
device's WireGuard key is generated locally and kept (`key_file:` to place it),
so the device keeps its identity and its address.

Mesh settings in a daemon's `tunnels.yaml`, next to `coord:` — the console
edits the same ones:

```yaml
mesh:
  enabled: true
  coord: server.example.com:7012
  pins: ["sha256:…"]
  name: laptop
  advertise_routes: ["192.168.1.0/24"]   # share a LAN
  advertise_exit_node: true              # offer to be an exit device
  exit_node: home-server                 # send this device's traffic out via a peer
```

`calabi mesh up --coord … --pin … --auth-key …` runs the mesh alone in the
foreground, without the daemon — for a quick test; it exits when its connection
to the coordinator ends. `calabi mesh status` asks the running daemon.

### ACLs

Without `CALABI_COORD_POLICY_FILE`, every device in a meshnet reaches every other.
With it, a JSON file of groups and rules decides who reaches whom, on which
ports. It hot-reloads on change. If the file is broken when the coordinator
starts, **it fails closed** (deny everything) and says so loudly, rather than
falling back to allow-all; fix the file and it recovers without a restart. A
broken edit while it runs is logged and the previous policy stays in force.

An ACL saved for a meshnet through the admin API
(`PUT /admin/meshnets/<id>/acl` on `CALABI_COORD_MESH_ADMIN_ADDR`) takes over
from the file — or from allow-all — for that meshnet. The admin API has no call
that removes it again; without `CALABI_COORD_DB_DSN` it lasts until the
coordinator restarts.

### Subnet routers and exit devices

Advertising a route or offering to be an exit device works on every platform.
The forwarding half — turning on IP forwarding and NAT so packets actually cross
— **is automated on Linux only**; elsewhere the device advertises and you
configure the OS yourself. *Using* an exit device — sending your default route
through it — works on Linux, Windows and macOS.

---

## Phones and the desktop console

The Android app and the client's console (`:7400`, the desktop app's window)
connect to your server from their sign-in page: **Connect to a self-hosted
server** — an invite link or code, or the coordinator's address and a key. The
phone joins the mesh and does not serve tunnels. The console's daemon starts
again in place as your server's device, on the same port. A daemon run with
`--config` keeps the server its file names, and one whose `CALABI_MODE` is set
in its environment, or a service installed with an API key, does not switch.

If the coordinator later presents a different certificate, the app stops
connecting to it and shows the fingerprint it trusted and the one presented now,
side by side. Trusting the new one applies to that certificate only. Until then
the app keeps trying with its old trust, so putting the old certificate back
brings the device back without anyone touching it. The edge's certificate
changes need nothing from anyone: the coordinator passes them on.

**Devices, tunnels, usage.** Both apps list the network's devices. From a
coordinator with a database they also show tunnels and this month's traffic:

- The tunnels are the ones the desktop daemons report — name, type, public
  address, local address, whether it is up, bytes — every five minutes and
  whenever the list changes, with the mesh on or off. A device counts as up for
  its tunnels while it is on the mesh or its reports keep coming. Tunnels run by
  `calabi http` are not listed.
- This month's traffic is tunnel traffic plus relayed mesh traffic, counted
  once, on the sending side. Direct connections between devices do not pass
  through your server and are not counted. Days and months follow the time zone
  of whoever is looking. The coordinator keeps 92 days of tunnel traffic.
- Without `CALABI_COORD_DB_DSN` the tunnel list lives in the coordinator's
  memory (the daemons fill it again within minutes of a restart) and there is no
  traffic record; the apps say so instead of showing zero.

**Leaving.** *Disconnect and forget this server* in the console, *Leave this
server* on the phone: the coordinator is told the device has left, after which
it takes a new invite to come back, and the app forgets the server. The console
also deletes its `tunnels.yaml`, tunnels included — it says how many first — and
goes back to the calabi.net sign-in page. The device key stays, so joining the
same coordinator again is the same device.

---

## What self-hosting does *not* give you

These are control-plane features. The commands exist in the binary but need a
calabi.net account:

- `calabi login / logout / org / certs / domains / clients`,
- a managed multi-region edge fleet and edge discovery,
- accounts, organizations, billing, the web console at console.\<host\>,
- automatic Let's Encrypt certificates for tunnel domains.

Note what is *not* on that list: the mesh. `calabi-coord` is a full coordinator,
not a demo — its own keys, ACLs, relays and devices. What the hosted platform
swaps in is *whose* accounts it trusts and metering; the meshing itself is this
code. A self-hosted server is yours alone and cannot be pointed at the hosted
platform's devices, and platform users never need to run one.

---

## Production notes

- **Back up the coordinator's state**: the database, `coord-grant.key` and
  `coord-tls/`. Without them every device joins again with a new invite.
- Keep the edge's `state.dir`: the subdomain counter and its certificates live
  there.
- Keep the admin addresses (the coordinator's `:9122` and mesh admin, the edge's
  `:9101`) on a private interface.
- `CALABI_ENV=production` on both: each refuses to start on a fail-open default.
- Process-wide backpressure caps on the edge are available via env
  (`EDGE_GLOBAL_MAX_CONNS`, `EDGE_GLOBAL_ACCEPT_RATE_PER_SEC`).
- Run the device daemons as services (`calabi daemon install --config …`) so they
  come back on boot.

---

## Upgrading from 1.12 or earlier

1.13 makes the coordinator every device's identity, for tunnels as well as the
mesh:

- **The edge's token table is gone.** An edge now needs `mode: standalone` and
  the coordinator's public key, and accepts devices by the coordinator's grants.
  A config that still lists `accepted_tokens` is refused at start.
- **`tunnels.yaml` no longer names the edge.** `server`, `token`, `token_env`,
  `insecure`, `ca_file`, `trust` and `pins` at the top level are refused in a
  file you wrote (they are dropped, with a warning, from the console's own).
  Join the coordinator (`calabi join`, or a `mesh:` block) and the edge comes
  from it.
- **The one-shot commands** no longer read `CALABI_SERVER`, `CALABI_TOKEN`,
  `CALABI_EDGE_PIN` or `CALABI_EDGE_TRUST` in standalone mode.
- **A standalone relay always checks grants.** Give it the coordinator's key.
- A coordinator without certificate files used to serve plaintext; since 1.13 it
  serves a self-signed certificate. Pin its fingerprint on devices, or set
  `CALABI_COORD_TLS=off`.
- `calabi mesh down` now keeps a self-hosted device off the mesh across
  restarts; `calabi mesh up` with no arguments puts it back.

---

## License & contributing

Open source under the terms in [LICENSE](../LICENSE) (see also `NOTICE`). Issues and
patches to the edge core, client core, coordinator and the local console are welcome.
