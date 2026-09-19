# Your own Calabi server

The coordinator and the edge on one machine, with Docker. Devices join with an
invite; from then on the same device has tunnels and the mesh.

- **coord** (`calabinet/calabi-coord`) — the devices of your network, their
  `100.64.x.x` addresses, ACLs and invites. It signs the grant each device signs
  in to the edge with.
- **edge** (`calabinet/calabi-edge`) — public tunnels to your devices' local
  services, and the relay the mesh falls back on when two devices can't reach
  each other directly.

## Before you start

- A Linux machine with a public address — a small VPS is enough.
- Docker with Compose, or Podman with `podman compose`. Where this README says
  `docker compose`, `podman compose` works the same.
- These ports open to the internet:

  | port | for |
  |---|---|
  | 7012/tcp | devices ↔ the coordinator |
  | 7443/tcp | devices' tunnel connections |
  | 80/tcp, 443/tcp | visitors to HTTP tunnels |
  | 20000–20999/tcp and /udp | visitors to TCP and UDP tunnels (a port a tunnel asks for with `--remote-port` has to be open too) |
  | 3340/tcp, 3478/udp | the mesh relay, and STUN |

- For HTTP tunnels, a domain with a wildcard record pointing at the machine
  (`*.tunnels.example.com`). The mesh and TCP/UDP tunnels need none.

## Start

```bash
cp .env.example .env    # set CALABI_PUBLIC_HOST and CALABI_ADMIN_TOKEN (and CALABI_TUNNEL_DOMAIN)
docker compose up -d
```

## Add a device

```bash
docker compose exec coord calabi-coord invite --note "my laptop"
```

It prints a `calabi://join` link and a QR code. An invite admits one device
within 24 hours unless you say otherwise: `--uses 5`, `--reusable`,
`--expires 72h`, `--no-expiry`, `--tag tag:server`.

- **A computer:** `calabi join "calabi://join?…"`, or the client's console
  (`http://127.0.0.1:7400`) → **Connect to a self-hosted server** → paste the
  link.
- **A phone:** the Calabi app → **Connect to a self-hosted server** → scan the
  code.

Then, on that computer, `calabi http 8080` gives the service on port 8080 a
public address under your tunnel domain, and the device reaches the others in
the network at their `100.64.x.x` addresses. The mesh can be switched off on a
device; its tunnels keep working.

## Devices

```bash
docker compose exec coord calabi-coord device list
docker compose exec coord calabi-coord device disable 3    # the ID column
docker compose exec coord calabi-coord device enable 3
docker compose exec coord calabi-coord device delete 3
docker compose exec coord calabi-coord device approve 3    # when the network requires approval
```

A disabled or deleted device leaves the mesh at once; its tunnels stop when the
grant it holds runs out, within the hour.

```bash
docker compose exec coord calabi-coord authkey list
docker compose exec coord calabi-coord authkey revoke 2    # stops new devices joining with it
```

## Keeping it

- **Update:** `docker compose pull && docker compose up -d`. Pin a release with
  `CALABI_VERSION` in `.env`.
- **Back up the `calabi_coord-data` volume.** It holds the device registry
  (`coord.db`), the key the coordinator signs grants with, and its certificate,
  whose fingerprint every device has pinned. Without it, every device joins
  again with a new invite.
- Back up `calabi_edge-state` too: the edge's certificate and the counter behind
  tunnel names (`u000001`, …). A new edge certificate reaches the devices through
  the coordinator, with nothing for you to do.

## HTTPS

The edge serves HTTPS for your tunnel domain with a self-signed wildcard
certificate, so browsers warn. Automatic Let's Encrypt certificates are not
there yet.

## More

Running the coordinator and the edge on different machines, ACLs, subnet
routes, exit devices, and every setting:
[docs/self-hosting.md](../../docs/self-hosting.md).
