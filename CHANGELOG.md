# Changelog

What changed in each release, and what it means if you run Calabi.

Every entry is written from the user's side: what behaves differently now, not
what moved in the code. The binaries for each version, their checksums, and the
build manifest that ties them to a source commit are on the
[releases page](https://github.com/calabinet/calabi/releases).

This file starts at 1.8.0. Earlier releases have their artifacts and
verification instructions on the releases page, but no written changelog.

## 1.8.1 — 2026-09-09

A follow-up to 1.8.0, and almost entirely about things that reported the wrong
state: a tunnel that stayed down for five minutes after its network came back, a
console that called a working feature unavailable, and a startup line that
announced a problem which did not exist. Client only — the edge is unchanged, and
is rebuilt at the same version as always.

### Reconnecting after an outage

- **Fixed** — A regression in 1.8.0. When the control plane could not be reached
  at all — the ordinary shape of a network outage — the client classified it as
  "there is no edge in your region", a condition only a person can resolve, and
  dropped to retrying every five minutes. Tunnels came back up to five minutes
  after the link did, while the mesh returned in seconds. 1.8.0's note that
  network failures retry with a back-off capped at one minute was true of the
  policy and not of this path; it is true of both now.
- **Fixed** — A tunnel session whose link died waited for the operating system to
  notice, which took minutes. The session now watches for silence from the edge
  itself and drops the session after three missed heartbeats (45 seconds by
  default), the same way the mesh already did.
- **Fixed** — Suspending and resuming a machine is detected on the tunnel plane
  too, instead of only on the mesh.
- **Added** — The session watchdog logs its interval and deadline when it arms.
  A mechanism that is silent when all is well cannot otherwise be told from one
  that never started.

### Mesh

- **Changed** — MagicDNS no longer takes over the system resolver unless asked.
  It was withdrawn from the documentation before 1.8.0 — it is Linux-only, while
  the machines someone would type `web-01.mesh` on are mostly not — but the code
  kept running, so it still rewrote `/etc/resolv.conf` on every Linux node. A
  daemon that then exited ungracefully (a crash, a reboot, a binary swapped under
  a running service) left that file pointing at a resolver which was no longer
  there, and the host had no DNS at all, for anything. To keep it, set
  `magic_dns: true` in the daemon's mesh config or pass `calabi mesh up
  --magic-dns`. A machine already in that state is repaired by restoring
  `/etc/resolv.conf` from `/etc/resolv.conf.calabi-orig`.
- **Fixed** — A machine that was rewriting subnet-alias traffic correctly could
  be told that it could not. The console re-derived that answer on every request
  by running `iptables`, and every failure — including losing a race for the
  iptables lock against the daemon's own rule installation, which is exactly what
  publishing another route triggers — was reported as "this machine cannot do
  it". It now reports what happened when the rules were really installed, and
  reports nothing at all when it could not find out.
- **Fixed** — Every `iptables` command the client runs now waits for the lock
  rather than failing the instant another process holds it. The same race could
  equally have failed a real rule installation, which fails silently.
- **Fixed** — The "cannot install" warning replaced the assigned alias mapping
  instead of appearing beside it, so a machine wrongly reported as incapable also
  lost sight of the rewrite it was performing.
- **Fixed** — A node that had not finished enrolling was shown as broken rather
  than as still starting.
- **Fixed** — The overview reported the relay row from whether the mesh was up
  rather than from whether the relay was actually carrying traffic, and switching
  region or egress node reloaded the entire page instead of refreshing the data
  that changed.
- **Added** — The mesh page reports the round-trip time to the relay separately
  from the end-to-end time to the peer. On a relayed path those are different
  measurements, and only one of them is a single leg.

### Diagnostics

- **Fixed** — The daemon announced "requested port busy — fell back" at startup
  when nothing was busy and nothing had moved. A dual-stack host reports a
  wildcard bind under a different name than the one requested, and the check
  compared the two spellings instead of the two ports.

## 1.8.0 — 2026-09-09

Mostly a mesh data-path release: several separate faults were making relayed
traffic far slower than the link could carry, and the tooling could not tell
them apart. Client and edge move together, as always.

### Mesh data path

- **Fixed** — Relay links could hold more than 20 seconds of queued data before
  putting it on the wire, so a busy link answered minutes late instead of
  dropping anything. Sends now go through a bounded queue with a 500 ms
  deadline. On a slow link, sustained round-trip time fell from 5.7 s to under
  200 ms.
- **Fixed** — A single peer that stopped reading could stall every other peer
  sharing the same relay: forwarding ran on the link's read goroutine, so one
  blocked write stopped the whole source link.
- **Fixed** — Relay frames were written in two pieces (a 5-byte header, then the
  payload). With `TCP_NODELAY` on, that interacted badly with delayed ACKs and
  serialised a stream that should pipeline. A loopback benchmark went from
  338 to 533 Mbit/s.
- **Fixed** — Data-path counters reset to zero whenever a relay socket was
  rebuilt, so totals went backwards.
- **Changed** — The mesh MTU floor is now 576 (was 1280), and can be set from
  the environment.

### Diagnosing a slow mesh

- **Added** — `calabi mesh relaytest` measures **one leg** of the relay path on
  its own, in per-second buckets, instead of only reporting an average over the
  whole run. `--oneway` isolates the sending direction, and works on direct
  paths too. A probe that does not complete its full duration no longer reports
  a rate at all — that number looked most like an answer exactly when it was not
  one.
- **Added** — `calabi mesh status` reports data-path counters that separate
  "we dropped it" from "the network dropped it", plus how long the writer spent
  blocked on the relay socket.

### Mesh subnet routing

- **Changed** — Published subnets are always exposed under a stand-in prefix
  (`100.96.0.0/11`) instead of their real addresses. The per-route toggle is
  gone: whether the rewrite can be installed is now detected by actually trying
  it, rather than asked of the one person with no way to know. Consumers need
  no changes.
- **Changed** — Only `/24` and smaller prefixes are accepted. A single host is
  written as a bare address.
- **Added** — Each meshnet has an alias-address budget (one `/24` by default),
  adjustable per organisation from the admin console. When an allocation fails,
  the device that asked for it now says so instead of silently publishing
  nothing.
- **Added** — The device lists in both consoles show the real → alias mapping,
  and a report lists devices that hold an alias block but have not been online
  for a long time.
- **Fixed** — Four address leaks in the alias pool; allocation is now a buddy
  allocator.

### Client

- **Fixed** — After a network outage lasting more than about 2.5 minutes, the
  client stopped reconnecting its tunnels permanently and waited for someone to
  click something in the local console. On a machine installed as a service
  there is nobody to click, so the only cure was restarting the service — while
  the mesh, which has no such limit, came back on its own. Network failures now
  retry indefinitely with a back-off capped at one minute. The "no edge in this
  region, switch manually" prompt still appears, because that one a user can act
  on, but the client keeps retrying underneath it.
- **Fixed** — Suspending and resuming a machine left the tunnel session holding
  a TCP connection the far side had long forgotten, and it was only noticed when
  the OS keep-alive gave up minutes later. Resume is now detected and the
  session re-established within seconds, the same way the mesh already did.
- **Fixed** — On Linux, shutting the mesh down non-gracefully could leave the
  machine's DNS permanently broken, and the breakage survived restarts.
- **Fixed** — A daemon installed as a service on Linux or macOS had no `HOME`
  and could not read its own credentials.
- **Fixed** — `calabi daemon install` now checks the SELinux label of the binary
  it is about to install, instead of producing a service that fails to start
  with no log entry.
- **Fixed** — When the control plane could not be reached, release builds
  reported a connection refused from `localhost` — describing the machine you
  are standing on rather than the thing that is broken.
- **Fixed** — `calabi mesh status` and `calabi mesh down` no longer assume the
  daemon is on `127.0.0.1:7400`, and gated commands ask the daemon for the local
  token instead of guessing its file path (every gated command returned 401 on
  macOS).
- **Fixed** — The throughput chart in the local console could report several
  GB/s. Two pollers on different intervals were summed into one counter and
  differenced against the wrong clock.
- **Fixed** — Linux archives shipped a binary without the execute bit, so the
  documented `tar xz && sudo mv calabi /usr/local/bin/` ended in "Permission
  denied".
- **Fixed** — The mesh page no longer presents `<name>.mesh` as an address you
  can type; MagicDNS is Linux-only and remains deferred.

### Release integrity

- **Fixed** — The build manifest recorded a set of linker flags that was not the
  set used to build the client, so `verify-reproducible-build.sh` reported all
  seven client artifacts as mismatched. The binaries were correct — the flag in
  question set a variable to its own default, changing no code — but linker
  flags feed Go's build ID, so the recorded flags could never reproduce the
  shipped bytes. Releases now record the flags the build actually used, and a
  release aborts if the manifest cannot reproduce its own artifacts. Nothing
  published before 1.8.0 was affected.
- **Fixed** — `-X main.defaultServer` had no effect because the variable was in
  a `const` block, so the previous release's stamped default was silently a
  no-op.
