# Developing Calabi

How to build the three programs and run them against each other on one machine
— no account, no public address, no DNS. That is the loop for changing code and
seeing the result.

For contribution rules, see [CONTRIBUTING.md](CONTRIBUTING.md). For running a
real server, see [docs/self-hosting.md](docs/self-hosting.md).

## What you need

**Go 1.25 or newer.** Nothing else for the client, the edge and the
coordinator. The Android app and the desktop shell need more — see
[below](#the-android-app-and-the-desktop-shell).

On Windows, run the shell commands here in Git Bash, and add `.exe` to the
binary names.

## Build

```bash
make build          # → bin/calabi, bin/calabi-edge, bin/calabi-coord
```

Or one at a time:

```bash
( cd apps/client       && go build -o ../../bin/calabi       ./cmd/calabi )
( cd apps/calabi-edge  && go build -o ../../bin/calabi-edge  ./cmd/calabi-edge )
( cd apps/calabi-coord && go build -o ../../bin/calabi-coord ./cmd/calabi-coord )
```

## Run all three on one machine

The coordinator hands out identities, the edge serves tunnels, the client joins
and opens one. Every address below is `127.0.0.1`.

### 1. A directory to work in

The programs keep their state next to themselves, so give them a directory of
their own and run everything from it:

```bash
mkdir -p ~/calabi-dev && cd ~/calabi-dev
cp /path/to/calabi/bin/{calabi,calabi-edge,calabi-coord} .
```

### 2. The edge's configuration and certificate

```yaml
# edge.yaml
node_label: dev-edge
region: dev
mode: standalone
coord_pubkey_file: ./coord.pub
state:
  dir: ./edge-state
control:
  addr: "127.0.0.1:7443"
http:
  addr: "127.0.0.1:8081"
https:
  addr: "127.0.0.1:8443"
sni:
  addr: "127.0.0.1:8444"
admin:
  addr: "127.0.0.1:9101"
log:
  level: info
  format: text
```

`-fingerprint` creates the edge's certificate and prints the fingerprint that
devices pin:

```bash
./calabi-edge -config edge.yaml -fingerprint
# sha256:b217ef79…
```

### 3. The coordinator

Start it **first**: it writes `coord.pub`, the key the edge waits for
([why](#why-does-the-coordinator-have-to-start-first)).

```bash
CALABI_COORD_GRPC_ADDR=127.0.0.1:7012 \
CALABI_COORD_ADMIN_ADDR=127.0.0.1:9122 \
CALABI_COORD_MESH_ADMIN_ADDR=127.0.0.1:9500 \
CALABI_COORD_MESH_ADMIN_TOKEN=dev-admin-token \
CALABI_COORD_GRANT_PUBKEY_FILE=./coord.pub \
CALABI_COORD_EDGE_ADDR=127.0.0.1:7443 \
CALABI_COORD_EDGE_PIN=sha256:b217ef79… \
CALABI_COORD_IDENTITY_ADDR= \
./calabi-coord
```

| Setting | What it does |
| --- | --- |
| `CALABI_COORD_GRPC_ADDR` | Where devices reach it. Invite links carry this address. |
| `CALABI_COORD_ADMIN_ADDR` | Health and metrics. |
| `CALABI_COORD_MESH_ADMIN_ADDR` + `_TOKEN` | The private ops API that `invite`, `authkey` and `device` use. |
| `CALABI_COORD_GRANT_PUBKEY_FILE` | Where it writes the public half of its grant signing key, for the edge. |
| `CALABI_COORD_EDGE_ADDR` | The edge it tells devices to use. |
| `CALABI_COORD_EDGE_PIN` | The edge's fingerprint from step 2. Optional — left out, the coordinator reads it from the edge once a minute. |
| `CALABI_COORD_IDENTITY_ADDR` | Empty: self-hosted, no identity service. |

### 4. The edge

```bash
./calabi-edge -config edge.yaml
```

It is up when five listeners are reported: `control`, `http`, `https`, `sni`,
`admin`.

### 5. An invite

```bash
./calabi-coord invite --admin 127.0.0.1:9500 --token dev-admin-token \
  --server 127.0.0.1:7012 --reusable --no-qr
```

It prints a `calabi://join?…` link carrying the coordinator's address, its TLS
fingerprint, and the key.

### 6. A device, kept away from anything installed

A client picks up credentials from your config home and opens a console on
`:7400` — the same places a Calabi you already have installed uses. Give the
test device its own ([why](#why-give-the-device-its-own-config-home)):

```bash
# devenv.sh — run every client command through this
HERE="$(cd "$(dirname "$0")" && pwd)"
export LOCALAPPDATA="$HERE/device-a"
export APPDATA="$HERE/device-a"
export XDG_CONFIG_HOME="$HERE/device-a"
export HOME="$HERE/device-a"
export CALABI_CONFIG=
export CALABI_MODE=
export CALABI_SERVER=
export CALABI_TOKEN=
export CALABI_API_KEY=
export CALABI_INSECURE=
export CALABI_STATUS_ADDR=127.0.0.1:7401
mkdir -p "$HOME"
exec "$@"
```

```bash
bash devenv.sh ./calabi join --no-start-daemon "calabi://join?…"
#   joined
```

For a second device, copy the script with `device-b` and another status port.

### 7. A tunnel

Serve something on `127.0.0.1:9999`, then:

```bash
bash devenv.sh ./calabi http 9999

#   tunnel: http://u000001.localtest.me  ->  127.0.0.1:9999
```

Fetch it. The printed URL leaves out the port, and `localtest.me` resolves only
if your DNS can reach the public internet, so the reliable form is:

```bash
curl -H "Host: u000001.localtest.me" http://127.0.0.1:8081/
```

With working DNS, `curl http://u000001.localtest.me:8081/` does the same thing.

The device's console is at `http://127.0.0.1:7401` — the port from
`CALABI_STATUS_ADDR`, not the usual `:7400`.

## The mesh relay

The edge serves the relay in the same process. Add to `edge.yaml`:

```yaml
role: both
relay:
  derp_port: 3340
  stun_port: 3478
  label: dev
```

and give the coordinator the relay's address, so it builds a one-region map:

```bash
CALABI_COORD_DERP_ADDR=127.0.0.1:3340 CALABI_COORD_DERP_STUN_PORT=3478 …
```

The edge then reports `relay role: relay listening` and `STUN responder
listening`.

The client side (`calabi mesh up`) creates a TUN device, so it needs
Administrator on Windows or root on Linux and macOS, and two devices to be
worth watching. [docs/self-hosting.md](docs/self-hosting.md) covers it end to
end.

## What the coordinator's warnings mean

A development coordinator prints several. They are expected here, and every one
of them is refused by `CALABI_ENV=production`:

| Warning | In development |
| --- | --- |
| no `CALABI_COORD_DB_DSN` … in-memory stores | Devices and ACLs are lost on restart. |
| built-in PLACEHOLDER derp map | No relay configured yet; see above. |
| generated a NEW grant signing key | Written to `coord-grant.key`; the edge needs the matching `coord.pub`. |
| the BUILT-IN dev key admits any caller | Anyone who can reach `:7012` can join. |
| minted auth keys are kept in memory | Invites are lost on restart. Mint another. |

If you are reproducing a production problem, set `CALABI_ENV=production` and
give it the real settings — that is the difference between the two.

## Tests

Each directory in `go.work` is its own module, so tests run per module:

```bash
for dir in $(grep -oE '\./[A-Za-z0-9/_.-]+' go.work); do
  ( cd "$dir" && go build ./... && go vet ./... && go test ./... )
done
```

CI runs the same loop on Linux, macOS and Windows, with `go test -short`. That
skips five tests whose answer depends on how busy the machine is — two relay
throughput benchmarks, one that spawns helper processes, one that spans real
timer ticks, and one that cross-builds for Android and iOS. Run without
`-short`, as above, on your own machine.

`make verify` checks that the tree is the published open-source tree.
`make verify-build` rebuilds a release and compares it byte for byte with what
was published — see [the README](README.md#releases-and-checking-them-yourself).

## The Android app and the desktop shell

Neither is built by CI; build them by hand when you change them.

- **Android** — JDK 17, Android SDK platform 35, NDK r27, gomobile. The Go core
  becomes an `.aar` via `scripts/mobile/build-core-android.ps1`, then Gradle
  builds the app. See
  [apps/client-android/README.md](apps/client-android/README.md).
- **Desktop shell** — Rust and the platform WebView; `cargo tauri build`. See
  [apps/client-desktop/README.md](apps/client-desktop/README.md).

The Go code both of them run is `apps/client`, which CI does cover.

## Questions

### Why does the coordinator have to start first?

It generates the key it signs device grants with and writes the public half to
`coord.pub`. The edge admits devices by checking grants against that key, so it
waits for the file.

### Why give the device its own config home?

A client reads its credentials and device identity from your config home, and
its console takes `127.0.0.1:7400`. Without the override, a test device signs
itself in over the credentials of a Calabi you actually use, and its console
collides with the installed one's.

### Can I point a dev client at calabi.net instead?

Yes — `calabi login` with your account, no local coordinator or edge. Use that
for changes to the client alone. The local stack is what lets you change the
edge or the coordinator and see the effect.

### The client connects but the tunnel returns nothing.

Check the port. The tunnel URL is printed without one because a real edge serves
`:80`, while `edge.yaml` here uses `:8081`.
