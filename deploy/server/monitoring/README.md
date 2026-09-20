# Monitoring a self-hosted server

Prometheus, three alerts, and the tests that prove they fire. Everything here
runs on your machine and reaches nothing of ours.

## Start it

From `deploy/server`:

```bash
docker compose -f docker-compose.yml -f monitoring/docker-compose.monitoring.yml up -d
```

Prometheus serves `127.0.0.1:9090`. It is not exposed — reach it over SSH:

```bash
ssh -L 9090:127.0.0.1:9090 you@your-server
```

Then open `http://127.0.0.1:9090` → **Status → Targets**. Both `coord` and
`edge` should be **UP**. Alerts are under **Alerts**.

## What it scrapes

| Job | Address | Comes from |
| --- | --- | --- |
| `coord` | `127.0.0.1:9122` | `CALABI_COORD_ADMIN_ADDR` in `../docker-compose.yml` |
| `edge` | `127.0.0.1:9101` | `admin.addr` in the edge config that compose writes |

Both are health and metrics only. Neither accepts commands.

## The alerts

| Alert | Fires when |
| --- | --- |
| `CalabiTargetDown` | Either program stopped answering for 3 minutes. |
| `CalabiEdgeFailingVisitors` | The edge has been failing or shedding visitor traffic for 10 minutes. |
| `CalabiCoordRPCErrors` | The coordinator has been failing device RPCs for 10 minutes. |

`CalabiTargetDown` is the one that matters most, because it is the only one
that catches a program being **gone**. The other two need metrics to be
flowing, and a program that crashed emits nothing — a dead service is quieter
than a healthy one.

### What they deliberately ignore

`CalabiEdgeFailingVisitors` counts only outcomes your server controls. It stays
silent for:

- **Your tunnel's upstream being down** (`open_upstream_failed`) — see below.
- **Your own access rules** refusing visitors: rate limits, IP restrictions,
  connection and daily caps, basic auth, OAuth. That is the policy you
  configured, working.
- **Strangers scanning your address** (`no_tunnel`, `sniff_failed`). A public
  edge is scanned continuously. It is not a fault.

### If you run the services behind your tunnels

Then `open_upstream_failed` **is** yours to fix, and you probably want to hear
about it. In `alerts.yml`, add it to the list:

```
outcome=~"internal_error|replay_head_failed|global_rate_limited|global_conn_capped|open_upstream_failed"
```

One test case expects that outcome to be ignored, so it will go red after this
change — which is how you confirm the edit took effect. Delete that case, or
flip it to expect an alert.

## Test the rules before you trust them

```bash
cd deploy/server/monitoring
docker run --rm -v "$PWD:/r:ro" --entrypoint promtool prom/prometheus \
  test rules /r/alerts_test.yml
```

Do this after any edit. `promtool check rules` only checks that a rule
*parses* — a rule naming a metric nothing emits parses perfectly, loads without
a warning, and then never fires, which looks exactly like a healthy server.
These tests evaluate the rules against synthetic data, so a rule that selects
nothing fails here instead of silently never firing.

## Useful queries

Paste these into Prometheus's expression browser, or into Grafana if you run
one.

```promql
# Visitor requests by type and outcome — the first thing to look at.
sum by (proxy_type, outcome) (rate(calabi_edge_visitor_requests_total[5m]))

# Throughput through the edge, both directions.
sum(rate(calabi_edge_bytes_transferred_total[5m]))

# Tunnels currently registered.
sum by (proxy_type) (calabi_edge_active_proxies)

# Devices connected to the edge.
calabi_edge_active_sessions

# Coordinator RPCs by method and result.
sum by (handler, code) (rate(calabi_handler_requests_total{svc="calabi-coord"}[5m]))

# Versions of what is running.
calabi_build_info
```

## Getting notified

Prometheus shows firing alerts in its own UI but does not send anything.
For email, Slack or a webhook, run
[Alertmanager](https://prometheus.io/docs/alerting/latest/alertmanager/) and
point Prometheus at it — `prometheus.yml` has the block to uncomment.

## Questions

### Why does Prometheus use the host's network?

The coordinator and the edge bind their admin ports to `127.0.0.1`, so nothing
off the machine can reach them. A container on a bridge network cannot reach
them either. Sharing the host's network namespace lets Prometheus scrape them
without opening those ports any wider.

### Can I monitor several servers from one Prometheus?

Yes — add a target per server in `prometheus.yml` and drop `network_mode:
host`. That means exposing each server's admin port to the machine Prometheus
runs on, so put them on a private network, not the internet.

### Does any of this reach calabi.net?

No. Prometheus scrapes your two containers over loopback and stores the data in
a volume on your machine.
