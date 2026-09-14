# Changelog

What changed in each release, and what it means if you run Calabi.

Every entry is written from the user's side: what behaves differently now, not
what moved in the code. The binaries for each version, their checksums, and the
build manifest that ties them to a source commit are on the
[releases page](https://github.com/calabinet/calabi/releases).

This file starts at 1.8.0. Earlier releases have their artifacts and
verification instructions on the releases page, but no written changelog.

## 1.10.0 — 2026-09-14

The largest release since the mesh shipped, and most of it answers one question
asked twice: **who may reach this, and can you find out afterwards who did.**
Tunnels gain organization-wide access rules, a per-visitor rate limit and access
records. The mesh gains access rules written about *people* rather than
machines, a switch that belongs to the device's owner, and connection records.
Client and edge move together, as always.

**Three things behave differently for setups that already exist.**

- An IP allow list of `0.0.0.0/0` no longer counts as access protection, and
  neither does a deny list on its own. If your organization requires protection,
  tunnels configured that way now appear in the violations list. Nothing that is
  running is stopped.
- `--ip-allow` and `--ip-deny` now take effect on calabi.net. They used to be
  accepted, noted as self-hosted-only, and discarded; a tunnel started with them
  is now really restricted by them.
- **Upgrade your self-hosted edges along with the client.** An edge older than
  1.10.0 does not understand a tunnel that references an organization's sign-in
  application, and serves that tunnel **with no sign-in at all** rather than
  refusing. Older edges also collect no access records.

### Tunnels

- **Added** — **Access records.** The edge now records, per tunnel and per hour,
  which visitor addresses connected and how each connection ended. Off by
  default, enabled per organization, with a retention period you choose. These
  are connections, not requests: one keep-alive connection carrying fifty
  requests is one row. Request lines, paths, headers and user agents are not
  recorded — that is the local console's job, on your own machine. A tunnel
  being scanned cannot make the table grow without bound: at most 256 distinct
  addresses per tunnel per hour are listed individually, and the rest are
  counted together.
- **Added** — **Reusable IP policies, and an organization baseline.** Name an
  allow/deny list once and reference it from any number of tunnels instead of
  copying addresses into each. An organization can require that every tunnel it
  publishes has access protection, and can name a default IP policy applied to
  new tunnels that arrive without any — without which `calabi http 8080` is not
  governed by the baseline, it is refused by it.
- **Added** — A second baseline covering **raw ports only**: TCP, UDP and SNI
  tunnels must carry IP rules. The people willing to publish an unprotected demo
  link and the people willing to publish an unprotected database port are not
  the same people, and one switch for both made them choose neither. This also
  closes a gap: a raw-port tunnel carrying Basic Auth used to count as
  protected, while the edge — which passes those bytes through untouched — never
  asked anyone for a password.
- **Added** — **Organization sign-in applications.** An OAuth client secret is
  now stored once for the organization instead of being copied into every
  tunnel's configuration, where anything that could read the tunnel list could
  read it. Tunnels reference the application by name, and the edge fetches the
  credential over its own authenticated connection when it serves one. Deleting
  an application that tunnels still reference is refused, and says how many.
- **Added** — **A per-visitor rate limit** (`per_ip_per_minute`) beside the
  existing per-tunnel one. A single cap shared by all visitors is also the lever
  an abuser pulls to take the tunnel down for everyone; the two now apply
  together, and the existing setting still means exactly what it meant before.
- **Added** — **Offline notification**, per tunnel and off by default. A tunnel
  that stops serving can email you instead of waiting for somebody to hit a 502.
  Ten minutes of grace, so a reconnect or a deploy does not trigger it, and one
  message per outage rather than one per report.
- **Added** — Tunnels can be **disabled automatically after N days with no
  visitor**. This is the only setting here that touches something already
  running, so it acts only when it can tell "nobody used it" apart from "we were
  not watching": access records must be on, and must have been on long enough.
- **Changed** — **Every refusal the edge serves now looks the same.** Being
  turned away by a password prompt, by a sign-in that was declined, or by a
  sign-in that did not complete used to produce a bare line of internal text
  with nothing to quote at support, while an IP refusal produced a proper page.
  All of them now carry the same page, a `CAL-xxxx` code and a warning mark —
  and none of them tell a stranger anything about the organization's account.
- **Fixed** — The client now reports whether the edge **applied** the security
  flags it was given, instead of inferring it from its own `--standalone`
  setting. A self-hosted edge wired to a control plane does not apply them,
  which the client had no way to detect: `--basic-auth` went nowhere, both
  consoles correctly showed no protection, and the warning that would have said
  so was suppressed by the very flag that made it wrong.
- **Fixed** — Two ways the edge's port pool disagreed with the tunnels that
  actually exist. At startup the pool was empty, so the first claim could hand
  out a port a live tunnel held — and the loser was deleted. And a port
  persisted during a session was not marked as taken, so the same number was
  offered again and the claim was refused with "remote port already bound",
  leaving a tunnel waiting for a client that was already connected. Ports are
  now reserved when the tunnel is persisted and released when it is deleted.
- **Fixed** — An installed agent never reported whether it could reach the
  service it forwards to. The console showed such tunnels as online while the
  local probe had been failing since the agent started; only interactive
  sessions reported. Agents carry their credential in the environment, and the
  health reporter was the one code path that looked only in the credentials
  file.
- **Fixed** — A tunnel that has not been claimed no longer has its configuration
  broadcast to every edge, self-hosted edges included.
- **Changed** — The edge reports its own version, so both consoles can show what
  each edge is running.

### Mesh

- **Added** — **Access rules can name people.** Selectors were all machines —
  names, tags, groups of machines — so "each person may reach only their own
  devices" could not be written down at all; it had to be maintained by hand,
  per person, per laptop. There are now `user:`, `autogroup:member` and
  `autogroup:self`, and a group may contain users, so a rule keeps meaning the
  right thing after somebody replaces a machine.
- **Added** — **Block incoming connections**, on the device, for its owner. The
  device stays visible and can still start connections, but accepts none. It is
  enforced on the machine itself rather than by the coordinator, so it holds
  when the coordinator is unreachable and in the many organizations that never
  wrote a rule at all, and it outranks any rule that would have allowed the
  connection. Replies on connections the machine itself started still arrive.
- **Added** — **Connection records.** Which device talked to which, in which
  hour, how many bytes, and whether it went direct or through a relay. No
  endpoint addresses and no public IPs are in it — the location trail those
  would form is exactly what the mesh deliberately does not keep. Retention is
  set by the operator; an organization can switch the records off and delete
  what is stored. They are reported by the clients themselves, which the console
  says plainly: this is evidence, not proof, and it is never an input to an
  authorization decision.
- **Added** — **Members can manage their own devices** — rename, disable, delete
  — instead of looking at a page of greyed-out buttons. The thirteen actions
  that decide how the *network* behaves (approvals, tags, routes, rules, relays,
  services) stay with administrators. A device carrying a tag belongs to the
  organization rather than to a person, and a device publishing an approved
  route cannot be deleted by its owner until the route is withdrawn.
- **Added** — Removing a member now **disables the devices in their name**
  before the membership goes, and the confirmation says so. A coordinator
  session had no expiry and a node re-authenticated only at enrollment, so a
  laptop that never disconnected stayed inside the private network
  indefinitely. Tagged devices are left alone: stopping a CI runner because
  whoever installed it left is an incident, not offboarding.
- **Added** — Devices report their operating system; the peer list shows the
  machine name instead of a public key, says who owns each device and which
  services it offers, and can be filtered by name, address or service.
- **Added** — A device waiting for approval is told so, and a client that cannot
  connect can say why.
- **Fixed** — A device carrying a tag had no personal owner, which left a hole in
  the rule that lets members manage their own devices.

### Accounts and organizations

- **Added** — **Per-member quotas.** An organization can set a default quota that
  new members inherit, and override it for one person: tunnels, raw-port tunnels
  and mesh devices. Personal limits are not reserved capacity — the organization
  total is still the ceiling, and the limit that applies is the smaller of the
  two. Administrators are not bound by the default, but are bound by a limit set
  for them specifically. Going over only blocks creating something new; nothing
  existing is stopped.
- **Removed** — The limit on how many clients an organization may register. This
  product does not charge for machines, and the limit had never been enforced
  anywhere; it is gone rather than quietly switched on.
- **Changed** — Removing a member now also stops their tunnels and revokes the
  API keys they minted. Until now a removed member's connected daemon kept
  serving on the organization's domain and their keys kept managing its tunnels
  — the console door closed, the data plane's did not. Tunnels running on an
  organization agent are left alone.
- **Changed** — Switching organizations ends the session you switched away from.

### Local console

- **Fixed** — The console occasionally bounced to its login screen, and opening a
  new tab worked. Two parts of the daemon refreshed the sign-in at the same time
  and one of them was told to sign in again; every part now shares one refresh.
- **Changed** — The tunnel pages were rebuilt to match the web console: creating
  one is a series of steps rather than one long form, the protocol is shown as a
  badge, and the quota a member has left is shown before they start instead of
  when the create fails.

## 1.9.0 — 2026-09-11

A security release. Most of it closes holes found in a review of the mesh after
it shipped; the rest concerns the edge, the self-update, and who may use the
local console.

**Upgrade clients before the coordinator.** A 1.9.0 coordinator refuses to enroll
nodes that speak an older mesh protocol — every client before 1.9.0 — while a
1.9.0 client still enrolls with an older coordinator. If you run your own
coordinator, update your clients first. Tunnels are not affected either way.

### Mesh

- **Changed** — Mesh protocol 2. Enrolling now proves possession of the node's
  private key — the coordinator issues a one-time challenge and the node answers
  it with the key — and returns a session token that every later call from that
  node carries. Before, those calls (fetching the network map, reporting
  endpoints and service health) identified the node only by its number, so
  anyone who could reach the coordinator could read an organization's map or
  overwrite a node's endpoints, and a member of an organization could enroll as a
  colleague's device. A coordinator on this version refuses nodes older than
  protocol 2 and tells them to upgrade.
- **Fixed** — A member could advertise a colleague's mesh address as a subnet
  route and draw that colleague's traffic. Routes inside the mesh's own address
  range are now refused, a route overlapping one that another node already
  publishes waits for an admin instead of being approved automatically, and
  clients ignore a peer's claim to route another node's address.
- **Changed** — Two devices enrolling under the same name no longer share it: the
  second gets a `-2` suffix. Before, a newcomer could inherit whatever ACL rules
  granted by device name. If your ACLs name devices, check they still point where
  you meant.
- **Changed** — Only a credential that can write may enroll a node. A read-only
  API key is refused.
- **Fixed** — One organization could fill the coordinator's table of pending
  enrollment challenges and stall enrollment for everyone. The table is now
  bounded per network.
- **Fixed** — One organization could exhaust the shared pool of subnet-alias
  addresses. The per-network budget is now capped.
- **Fixed** — Enrollments racing each other could exceed the seat limit.
  Enrollment within one network is now serialized.
- **Fixed** — A node that reconnected quickly could be left on a stream that no
  longer received map updates — including an ACL an admin had just tightened —
  until a periodic refresh up to 15 minutes later.
- **Changed** — A service added from the console can only point at the device
  itself (loopback). An arbitrary target made every member's machine probe
  whatever it could reach. A device declaring its own services is unaffected.
- **Fixed** — With relay authentication on, a relay no longer forwards packets
  between two different networks, which let one organization run up another's
  relay usage.
- **Fixed** — A coordinator whose auth-keys file is set but unreadable now refuses
  to start, instead of falling back to a built-in development key.
- **Fixed** — A signed-in client whose tunnel session stayed up for a long time
  let its access token expire, after which the mesh's next re-enrollment was
  refused every 30 seconds, indefinitely. The client now refreshes the sign-in
  once when the coordinator refuses it, and retries.
- **Removed** — The coordinator's relay-usage pull (`usage_collection` in the
  relay map, `RELAY_USAGE_TOKEN`) never worked and is gone. A map file that still
  mentions it loads as before.

### Edge

- **Fixed** — Requests forwarded between edges in the same region skipped OAuth
  authentication, Basic Auth and rate limiting; only IP rules applied. The full
  set now applies on that path too.
- **Fixed** — After OAuth authentication, the redirect back only goes to a path on
  the same site.
- **Fixed** — An ACME http-01 challenge is answered only under the domain it was
  issued for. On calabi.net, a certificate for your own domain now also requires
  the domain to be verified in your organization.

### Local console

- **Changed** — Visitors from another machine must enter the console's **unlock
  secret**. The console hands its write token to whoever can load it, and once it
  was bound beyond loopback nothing checked who that was; it also answered pages
  that pointed their own name at this machine (DNS rebinding). On the machine
  itself nothing changes. The secret is generated on first start, saved as
  `console-secret` in the data directory, and printed in the log when the console
  listens beyond loopback (`docker logs` for the container image); set
  `CALABI_STATUS_SECRET` to choose your own. Five wrong attempts pause that
  address for a few minutes, and an unlock lasts 12 hours. The console is still
  plain HTTP: across a network you don't trust, use an SSH tunnel or an HTTPS
  proxy.
- **Fixed** — Another website could make the console sign the daemon into that
  site's account: the login endpoint needs no token, and nothing checked where
  the request came from. Cross-site requests are now refused.
- **Changed** — On Windows, a system service's data directory (credentials, mesh
  key) is restricted to SYSTEM, Administrators and the account running it; it was
  readable by every local user. Existing installs tighten on their next write.
- **Changed** — When the platform hides its commerce pages, the console no longer
  tells you to upgrade your plan. The feature the console called a "login wall" is
  now called OAuth authentication.

### Updates and connectivity

- **Changed** — The self-update manifest must carry a valid signature
  (`latest.json.sig` beside `latest.json`); the client will not move below the
  newest version it has seen unless the signed manifest says `"rollback": true`;
  and it only downloads installers from the manifest's own origin. If you
  distribute your own updates, `updatekit merge` now writes the signature.
- **Fixed** — Edge discovery gave the control plane 3 seconds to answer, DNS and
  TLS included. On a path that had just changed — a new egress IP, a re-dialled
  uplink — that failed every time. It now allows 10 seconds.
- **Fixed** — Two parts of the client refreshing the sign-in at once could spend
  the same refresh token and leave one with nothing; a refresh could also undo a
  region switch saved while it was in flight, or overwrite a sign-in made
  meanwhile.
- **Security** — Updated dependencies with known vulnerabilities: gRPC 1.82.1 and
  golang.org/x/text 0.39.0.

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
