# Calabi — Community Edition

Standalone **tunnel data plane**: an edge (`calabi-edge`) that accepts public
traffic and a `calabi` client that forwards it to your local services — TLS +
yamux, no account, no phone-home. This is the open-source data plane; the managed
control plane (accounts, orgs, billing, the global edge fleet) is a separate
hosted product and is **not** in this repository.

```
┌─────────────┐        TLS + yamux        ┌──────────────┐      your app
│  calabi     │ ────────────────────────► │  calabi-edge │ ───►  127.0.0.1:8080
│  (client)   │   control + data streams  │  (your VPS)  │
└─────────────┘                           └──────────────┘
   your laptop                            public IP / DNS        visitors ──┘
```

## Build

Requires Go 1.25+.

```bash
make build          # → bin/calabi-edge, bin/calabi
```

Or directly (on Windows, name the outputs `*.exe`):

```bash
( cd apps/calabi-edge && go build -o calabi-edge ./cmd/calabi-edge )
( cd apps/client      && go build -o calabi      ./cmd/calabi )
```

`make build` already adds the `.exe` suffix automatically on Windows. To
cross-compile (e.g. a Windows binary from a Linux box):
`GOOS=windows GOARCH=amd64 go build -o calabi-edge.exe ./cmd/calabi-edge`.

## Quick start (one edge, one tunnel)

```bash
# 1. the edge on a host with a public IP (or locally to try)
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

For multiple tunnels with auto-reconnect and a local web console, run the
supervisor daemon:

```bash
./calabi daemon --config tunnels.yaml   # then open http://127.0.0.1:7400
```

**Full guide** — edge config, per-tunnel security policy (IP allow/deny + HTTP
Basic auth), the local supervisor daemon, OS-service install, the `:7400`
writable console, and HTTPS options:
see **[docs/community-edition.md](docs/community-edition.md)**.

## What's in / out

| | |
|---|---|
| ✅ edge (HTTP / HTTPS / TCP / UDP), client, per-tunnel security (IP allow/deny + Basic auth) | |
| ✅ local supervisor daemon + read/write web console (`:7400`) | |
| ❌ rate limiting, header rewrite, OAuth login wall | (advanced access control — hosted product) |
| ❌ accounts / orgs / billing, managed multi-region edge fleet, the hosted web console | (control plane — hosted product) |

The control-plane commands (`calabi login / org / certs / domains / clients`)
print a "platform-only" notice in this edition.

## Contributing

Issues and patches to the edge core, client core, and the local console are
welcome. We use a **DCO** (Developer Certificate of Origin), not a CLA — every
commit just needs a sign-off:

```bash
git commit -s -m "your message"
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [DCO](DCO) for details. A CI check
enforces the sign-off on pull requests.

## License

Open source under the terms in [LICENSE](LICENSE) (Apache-2.0).
