<p align="center">
  <img src="docs/images/logo.svg" width="120" height="120" alt="Calabi">
</p>

<h1 align="center">Calabi</h1>

<p align="center">
  <img alt="Go" src="https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat-square&logo=go&logoColor=white">
  <img alt="WireGuard" src="https://img.shields.io/badge/WireGuard-mesh-88171A?style=flat-square&logo=wireguard&logoColor=white">
  <img alt="Platforms" src="https://img.shields.io/badge/Linux%20%C2%B7%20macOS%20%C2%B7%20Windows%20%C2%B7%20Android-amd64%20%C2%B7%20arm64%20%C2%B7%20armv7-4c8bf5?style=flat-square">
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

## What is Calabi?

Calabi makes a machine reachable when it has no public address — a laptop
behind NAT, a server behind CGNAT, a box inside a corporate network. Two ways:

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

              calabi-coord — every device's identity: who has joined, where
              the edge is, each device's mesh address, who may talk to whom
```

Nothing here opens an inbound port on your laptop. In both modes the client
dials out.

`calabi-coord` and `calabi-edge` together are your server. A device joins it
once, with an invite, and has tunnels and the mesh from then on; the mesh can be
off on a device while its tunnels run.

### What is in this repository

The data plane: the `calabi` client, the `calabi-edge` data node, and the
`calabi-coord` coordinator. Everything needed to run tunnels and a mesh on
your own machines is here, and self-hosted it needs no account and calls no
service of ours.

It also holds the Android app, which joins your own server with an invite, or
signs in to calabi.net and joins that organization's mesh.

The hosted platform at [calabi.net](https://calabi.net) runs this same data
plane and adds the control plane around it: accounts and organizations, a
managed edge fleet across regions, team access control, usage and billing, and
a web console. That part is a separate product and is not in this repository.

---

## Three binaries and an Android app

| component | what it is | where it runs |
|---|---|---|
| `calabi` | the client — opens tunnels, joins the mesh, serves the local web console | your laptop, a server, a Pi |
| `calabi-edge` | the data plane. `role: edge` accepts public traffic for tunnels; `role: relay` is a mesh relay + STUN responder; `role: both` does both | a host with a public IP |
| `calabi-coord` | the coordinator — every device's identity: invites, device registry, IP allocation, ACLs; names the edge and signs the grants it accepts | one host, reachable by your devices |
| Android app | puts the phone in a mesh as a device — your own server's or a calabi.net organization's — with exit devices and a Quick Settings tile; tunnels and usage read-only | an Android 8.0+ phone (arm64, armv7) |

The three binaries are pure Go, `CGO_ENABLED=0`, no runtime dependencies.
`calabi-coord` and `calabi-edge` together are your server; the client runs on
each device.

The Android app (`apps/client-android`) is Kotlin around the same Go client
code, bound in with gomobile (`apps/client/mobile`).

---

## Your server

- **Invites** — `calabi-coord invite` prints a `calabi://join` link, a QR code,
  and the same as a `calabi join` command line. By default an invite admits one
  device, for 24 hours.
- **Joining is the sign-in** — the coordinator tells a device where the edge is
  and signs the grant the edge lets it in with. A grant lasts an hour, and the
  device renews it.
- **Devices** — `calabi-coord device list | approve | disable | enable |
  delete`. A device you disable or delete is refused by the coordinator at once,
  and by the edge when its grant runs out, within the hour.
- **Tunnels and traffic in one place** — every joined daemon reports its tunnels
  to the coordinator, which, with a database, keeps their traffic by the hour
  for 92 days. The phone and the console show both.

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
- **One daemon** — every tunnel of a device in one process, with
  auto-reconnect, created in the console or read from a YAML file, installable
  as a boot-start OS service (Windows service / systemd / launchd).

## Mesh

- **Real WireGuard** — the data plane is WireGuard, keys generated on each device.
  `calabi-coord` never sees a private key and never sees plaintext.
- **Direct when possible, relayed when not** — devices discover each other's
  endpoints, measure latency to each relay over STUN, and hole-punch. A relayed
  path is the fallback, not the design.
- **Your own relay** — `calabi-edge` with `role: relay` (or `both`, as
  `deploy/server` runs it) is the relay. It moves already-encrypted packets
  between device keys and **cannot decrypt them**; the isolation is structural,
  enforced by a dependency test, not by a config flag.
  Run one relay or several, in as many regions as you like.
- **Stable addresses** — every device gets a `100.64.0.0/10` address that
  follows it across networks, on every platform.
- **A switch on each device** — `calabi mesh down`, or the console, takes a
  device out of the mesh and leaves its tunnels running; `calabi mesh up` puts
  it back.
- **ACLs** — a JSON policy file of groups and rules decides which devices may
  reach which, on which ports. It hot-reloads, and a broken file **fails closed**
  (deny all) rather than open.
- **Subnet routers and exit devices** — advertise a LAN behind one device so
  the whole mesh can reach it, or route a device's default traffic through a
  peer.
  Advertising works everywhere; the forwarding/NAT side is automated on Linux.
- **Per-day usage split** — the local console books mesh traffic as *direct* vs
  *relayed*, so you can see how much actually needed a relay.

## The local console

While the daemon runs it serves a web console on **`http://127.0.0.1:7400`** —
live tunnel list with traffic counters, a request inspector with one-click
replay, mesh peers and their transport, daemon logs, and create / edit / delete
tunnels straight from the browser. It talks only to the local daemon over
loopback. It is also where a machine joins your server: paste an invite — no
config file to write. Joined, it shows every tunnel on your server and this
month's traffic. Available in 10 languages.

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

Every release also has all three prebuilt, for 7 platforms each — `calabi-coord`
from 1.13 — and each as a docker image: `calabinet/calabi`,
`calabinet/calabi-edge` and `calabinet/calabi-coord`. They are built from this
repository; see [below](#releases-and-checking-them-yourself).

### The Android app

Needs JDK 17, the Android SDK (platform 35) with NDK r27, and gomobile. The Go
core is built into an `.aar` by `scripts/mobile/build-core-android.ps1`
(PowerShell, written for Windows), then the app by Gradle. Steps are in
[apps/client-android/README.md](apps/client-android/README.md).

---

## Quick start — your own server

`calabi-coord` and `calabi-edge` together are your server. On a Linux machine
with a public address and Docker Compose (or `podman compose`), [`deploy/server`](deploy/server)
runs both from one `.env`:

```bash
cd deploy/server
cp .env.example .env     # CALABI_PUBLIC_HOST, CALABI_ADMIN_TOKEN, and CALABI_TUNNEL_DOMAIN for HTTP tunnels
docker compose up -d

# an invite for each device: a calabi://join link and a QR code
docker compose exec coord calabi-coord invite --note laptop
```

Open 7012 and 7443 (devices), 80 and 443 (HTTP tunnels), 20000–20999 tcp/udp
(TCP and UDP tunnels), 3340 and 3478/udp (the mesh relay).

Then on each device — the Android app scans the QR code instead:

```bash
calabi join "calabi://join?…"    # joining is the sign-in: tunnels and the mesh both work now
calabi http 8080                 # → https://u000001.<your tunnel domain>
ping 100.64.0.2                  # another device, over WireGuard
```

The joined client's daemon is running: its console at `http://127.0.0.1:7400`
creates tunnels and switches the mesh off and on (tunnels keep working with it
off). The coordinator is the one identity a device has — it names the edge and
signs the grant the edge lets the device in with — so there is no token to copy
and no certificate to confirm for the edge.

**Full guide** — running the binaries without Docker, every coordinator and edge
setting, per-tunnel security policy, servers and fleets that join from a config
file, the `:7400` console, ACLs, subnet routers and exit devices:
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

The Android APK is not reproducible yet either. Its Go core records the
directory it was built in, so the same commit built in another directory gives
a different library. Each release's notes print the certificate the APK is
signed with; check it before installing:

```bash
apksigner verify --print-certs calabi-android.apk
```

---

## Common uses

- Test webhooks and OAuth/redirect callbacks against a service on your laptop.
- Share a work-in-progress dev server with a teammate or a client.
- Reach a homelab, NAS, or Raspberry Pi behind NAT / CGNAT — a tunnel if the
  public should see it, the mesh if only you should.
- SSH or a database port to a remote machine, over a TCP tunnel or over the mesh.
- Join machines across several clouds into one flat private network without
  peering VPCs.
- Route a laptop's traffic out through a machine at home via an exit device.
- Reach your machines from an Android phone, over your own mesh or a calabi.net
  one.

## Contributing

Issues and patches to the edge, the client, the coordinator, the local console
and the Android app are welcome. We use a **DCO** (Developer Certificate of Origin), not a
CLA — every commit just needs a sign-off:

```bash
git commit -s -m "your message"
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [DCO](DCO). A CI check enforces the
sign-off on pull requests.

## License

Open source under the terms in [LICENSE](LICENSE) (Apache-2.0).
