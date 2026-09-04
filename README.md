<p align="center">
  <img src="docs/images/logo.svg" width="120" height="120" alt="Calabi">
</p>

<h1 align="center">Calabi</h1>

<p align="center">
  <img alt="Go" src="https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat-square&logo=go&logoColor=white">
  <img alt="WireGuard" src="https://img.shields.io/badge/WireGuard-mesh-88171A?style=flat-square&logo=wireguard&logoColor=white">
  <img alt="Platforms" src="https://img.shields.io/badge/Linux%20%C2%B7%20macOS%20%C2%B7%20Windows-amd64%20%C2%B7%20arm64%20%C2%B7%20armv7-4c8bf5?style=flat-square">
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/License-Apache%202.0-3da639?style=flat-square"></a>
  <a href="https://github.com/calabinet/calabi/releases"><img alt="Release" src="https://img.shields.io/github/v/release/calabinet/calabi?style=flat-square&color=22d3ee&label=release"></a>
</p>

<p align="center">
  <a href="#releases-and-checking-them-yourself"><img alt="Reproducible builds"
     src="https://img.shields.io/badge/REPRODUCIBLE%20BUILDS-rebuild%20every%20release%20yourself-22d3ee?style=for-the-badge&labelColor=0e1630"></a>
</p>

<p align="center"><b>Self-hosted tunnels and a private WireGuard mesh</b></p>

<p align="center">
  English | <a href="README.zh-CN.md">中文</a>
</p>

---

Two different ways to reach a machine that has no public address, in one
codebase, running entirely on infrastructure you own — no account, no
phone-home, no telemetry.

- **Tunnels** — put `calabi-edge` on a host with a public IP. The `calabi`
  client opens one outbound TLS + yamux connection to it, and the edge forwards
  public HTTP/HTTPS/TCP/UDP traffic back down that connection to a service on
  your laptop or LAN. **Anyone on the internet can reach it.**
- **Mesh** — join your own machines into one private WireGuard network with
  stable `100.64.0.0/10` addresses. Peers hole-punch to each other when NAT
  allows and fall back to a relay you run yourself when it doesn't.
  **Only your machines can reach it.**

```
  TUNNELS — public traffic in                MESH — private machine-to-machine

  visitors                                     laptop ─────────────┐
     │                                            │  direct (UDP)  │
     ▼                                            │  hole-punched  │
 ┌──────────────┐                                 ▼                │
 │  calabi-edge │  public IP / DNS             ┌────────┐          │
 └──────┬───────┘                              │ NAT :( │          │
        │ TLS + yamux                          └────────┘          ▼
        │ (client dialed OUT)                      │            server
        ▼                                          ▼           (no public IP)
 ┌──────────────┐                          ┌───────────────┐
 │    calabi    │ ──► 127.0.0.1:8080       │  calabi-edge  │  relay: ciphertext
 └──────────────┘                          │  role: relay  │  only, never decrypts
   your laptop                             └───────────────┘

              calabi-coord — the mesh's coordinator: who is in the
              network, what address each node gets, who may talk to whom
```

Nothing here opens an inbound port on your laptop. In both modes the client
dials out.

---

## The three binaries

| binary | what it is | where it runs |
|---|---|---|
| `calabi` | the client — opens tunnels, joins the mesh, serves the local web console | your laptop, a server, a Pi |
| `calabi-edge` | the data plane. `role: edge` accepts public traffic for tunnels; `role: relay` is a mesh relay + STUN responder; `role: both` does both | a host with a public IP |
| `calabi-coord` | the mesh coordinator — node registry, IP allocation, ACLs, MagicDNS, the relay directory | one host, reachable by your nodes |

Pure Go, `CGO_ENABLED=0`, no runtime dependencies. Only tunnels? You need two of
them, and never have to think about `calabi-coord`.

---

## Tunnels

- **HTTP, HTTPS, TCP and UDP** — web apps, SSH, databases, game servers,
  anything that speaks TCP/UDP.
- **One multiplexed connection** — a single outbound TLS + yamux session per
  client, so there is nothing to open or forward on your side.
- **Custom domains + HTTPS** — point DNS at your edge and map a tunnel to
  `app.example.com`; the edge can terminate HTTPS.
- **Per-tunnel access control** — IP allow/deny lists on any tunnel, HTTP Basic
  auth and OAuth (Google/GitHub) on web tunnels, header injection/removal, and
  per-tunnel rate limits. Basic-auth passwords are bcrypt-hashed locally before
  they ever leave your machine.
- **Supervisor daemon** — every tunnel from one YAML file in one process, with
  auto-reconnect, installable as a boot-start OS service (Windows service /
  systemd / launchd) that restarts on crash.

## Mesh

- **Real WireGuard** — the data plane is WireGuard, keys generated on each node.
  `calabi-coord` never sees a private key and never sees plaintext.
- **Direct when possible, relayed when not** — nodes discover each other's
  endpoints, measure latency to each relay over STUN, and hole-punch. A relayed
  path is the fallback, not the design.
- **Your own relay** — `calabi-edge` with `role: relay` is the relay. It moves
  already-encrypted packets between node keys and **cannot decrypt them**; the
  isolation is structural, enforced by a dependency test, not by a config flag.
  Run one relay or several, in as many regions as you like.
- **Stable addresses + MagicDNS** — every node gets a `100.64.0.0/10` address
  that follows it across networks, plus a name (OS-level name resolution is
  Linux-only for now; the addresses work everywhere).
- **ACLs** — a JSON policy file of groups and rules decides which nodes may
  reach which, on which ports. It hot-reloads, and a broken file **fails closed**
  (deny all) rather than open.
- **Subnet routers and exit nodes** — advertise a LAN behind one node so the
  whole mesh can reach it, or route a node's default traffic through a peer.
  Advertising works everywhere; the forwarding/NAT side is automated on Linux.
- **Per-day usage split** — the local console books mesh traffic as *direct* vs
  *relayed*, so you can see how much actually needed a relay.

## The local console

While the daemon runs it serves a web console on **`http://127.0.0.1:7400`** —
live tunnel list with traffic counters, a request inspector with one-click
replay, mesh peers and their transport, daemon logs, and create / edit / delete
tunnels straight from the browser. It talks only to the local daemon over
loopback. Available in 10 languages.

---

## Build

Requires Go 1.25+.

```bash
make build          # → bin/calabi, bin/calabi-edge, bin/calabi-coord
```

Or directly (on Windows, name the outputs `*.exe`):

```bash
( cd apps/client       && go build -o calabi       ./cmd/calabi )
( cd apps/calabi-edge  && go build -o calabi-edge  ./cmd/calabi-edge )
( cd apps/calabi-coord && go build -o calabi-coord ./cmd/calabi-coord )
```

`make build` adds the `.exe` suffix automatically on Windows. To cross-compile:
`GOOS=windows GOARCH=amd64 go build -o calabi-edge.exe ./cmd/calabi-edge`.

---

## Quick start — a tunnel

```bash
# 1. the edge, on a host with a public IP (or locally, to try it)
./calabi-edge                                 # :7443 control, :8080 http

# 2. a local service to expose
python3 -m http.server 9000

# 3. the client, pointed at your edge
export CALABI_SERVER=127.0.0.1:7443
export CALABI_TOKEN=dev-token-please-change
export CALABI_INSECURE=1                       # dev: self-signed edge
./calabi http 9000 --domain app.localtest.me

# 4. visit through the edge
curl http://127.0.0.1:8080/ -H 'Host: app.localtest.me'
```

For several tunnels with auto-reconnect and the console:

```bash
./calabi daemon --config tunnels.yaml   # then open http://127.0.0.1:7400
```

## Quick start — a mesh

One coordinator, one relay, and as many nodes as you want.

```bash
# 1. the relay — calabi-edge in relay role, on a host with a public IP.
#    A relay needs no config file at all: no domain, no certificate.
CALABI_EDGE_ROLE=relay CALABI_EDGE_RELAY_LABEL=home \
  ./calabi-edge                               # :3340 relay (TCP), :3478 STUN (UDP)

# 2. the coordinator. authkeys.json maps an auth key to a meshnet (+ ACL tags):
#      { "my-secret-key": { "meshnet": 1, "tags": ["tag:laptop"] } }
CALABI_COORD_AUTHKEYS_FILE=./authkeys.json \
CALABI_COORD_DERP_ADDR=relay.example.com:3340 \
CALABI_COORD_DERP_STUN_PORT=3478 \
CALABI_COORD_GRPC_ADDR=:7012 \
./calabi-coord

# 3. every node joins (needs a tun device + privileges;
#    Windows ships wintun.dll inside the binary)
sudo ./calabi mesh up \
  --coord coord.example.com:7012 \
  --relay relay.example.com:3340 \
  --auth-key my-secret-key --name laptop

./calabi mesh status
```

Then `ping 100.64.0.x` between nodes — no port forwarding anywhere.

> **TLS between node and coordinator.** The client dials the coordinator over
> TLS by default and verifies it against the CA baked into the binary. For your
> own deployment either give `calabi-coord` a cert from your own CA and point
> nodes at it with `CALABI_EDGE_CA_FILE=/path/to/your-ca.pem`, or — on a trusted
> network only — set `CALABI_INSECURE=1` for plaintext. **The auth key crosses
> that connection**, so do not run it plaintext over the public internet.

To run the mesh as a background service instead of in the foreground, put a
`mesh:` block in the daemon config and use `calabi daemon install`.

**Full guide** — edge config, per-tunnel security policy, the supervisor daemon,
OS-service install, the writable `:7400` console, HTTPS, and the mesh in detail:
see **[docs/self-hosting.md](docs/self-hosting.md)**.

---

## Releases, and checking them yourself

Every release is published in two places with **the same files**: the
[GitHub Releases](https://github.com/calabinet/calabi/releases) page of this
repository, and `download.calabi.net`. Same version number, same bytes — the
GitHub Release is not a separate CI build, it is the same artifacts uploaded.

The point of publishing this source is that you do not have to take our word for
what is in those binaries. **They are built from this repository**, not from an
internal tree, and each release ships a `build-manifest.json` naming the exact
commit, toolchain, flags, and the one input that is not in this repo (the
platform's edge-CA root — a public certificate, carried in the manifest
verbatim). Rebuild them yourself:

```bash
curl -fsSLO https://download.calabi.net/latest/build-manifest.json
bash scripts/verify-reproducible-build.sh build-manifest.json
```

That clones this repository at the commit the manifest names, rebuilds every
released binary, and compares hashes. It needs the same Go version the manifest
names; a different one is the usual reason a check fails, and the script says so
up front.

It compares the **binary**, not the `.zip`/`.tar.gz` you downloaded, because
archives are not reproducible — tar+gzip and zip both record modification times,
so the same bytes packaged a second later hash differently. Use `SHA256SUMS` for
the archive: that answers "did my download arrive intact", a different question
from "was it built from this source".

**Not yet covered**, listed in the manifest itself so it stays honest: the
Windows desktop installer and the macOS `.pkg` (separate Rust/Tauri toolchains),
the docker images, and two inputs that ship as committed blobs rather than being
built here — the local console's compiled web bundle and the third-party
`wintun.dll`. Those are byte-identical for anyone building a given commit, but
this repository does not derive them from their own sources.

---

## Common uses

- Test webhooks and OAuth/redirect callbacks against a service on your laptop.
- Share a work-in-progress dev server with a teammate or a client.
- Reach a homelab, NAS, or Raspberry Pi behind NAT / CGNAT — a tunnel if the
  public should see it, the mesh if only you should.
- SSH or a database port to a remote machine, over a TCP tunnel or over the mesh.
- Join machines across several clouds into one flat private network without
  peering VPCs.
- Route a laptop's traffic out through a machine at home via an exit node.

## Contributing

Issues and patches to the edge, the client, the coordinator and the local
console are welcome. We use a **DCO** (Developer Certificate of Origin), not a
CLA — every commit just needs a sign-off:

```bash
git commit -s -m "your message"
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [DCO](DCO). A CI check enforces the
sign-off on pull requests.

## License

Open source under the terms in [LICENSE](LICENSE) (Apache-2.0).
