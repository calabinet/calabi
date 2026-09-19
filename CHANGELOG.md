# Changelog

What changed in each release, and what it means if you run Calabi.

Every entry is written from the user's side: what behaves differently now, not
what moved in the code. The binaries for each version, their checksums, and the
build manifest that ties them to a source commit are on the
[releases page](https://github.com/calabinet/calabi/releases).

This file starts at 1.8.0. Earlier releases have their artifacts and
verification instructions on the releases page, but no written changelog.

## Unreleased

Changes since 1.13.0, going into the next release.

### Mesh

- **Fixed** — **Switching organization kept the exit device of the one left.**
  The phone and the desktop went on showing it, and looked for a device of that
  name in the new organization; one there that offered an exit would have
  carried all the traffic. Switching to another organization or signing out now
  clears the exit device, and so does leaving a self-hosted server on the phone.
  Switching to the organization you are already in keeps it.

### Mobile

- **Fixed** — *Forgot password* on the sign-in page opened the page the reset
  email links to, which said the link was invalid or expired. It now opens the
  form that sends the email. calabi.net already forwards the old link there, so
  earlier versions of the app work too.

## 1.13.0 — 2026-09-19

**Your own server, as one thing.** `calabi-coord` and `calabi-edge` together are
a self-hosted Calabi server, and the coordinator is every device's identity. A
device joins it once — an invite scanned on the phone, pasted into the console,
or `calabi join` in a terminal — and from then on the coordinator tells it where
the edge is and signs the grant the edge lets it in with. The same device has
tunnels and the mesh, and the mesh can be switched off on it without losing the
tunnels. `deploy/server` runs the coordinator and the edge from one compose file
and one `.env`.

**What is in this repository and what is not.** **Your server**, **Tunnels**,
**Mesh**, **Local console** and **Mobile** below are changes in what this
release ships, built from this tree. The last section, **On calabi.net**, is the
hosted control plane: its code is not in this repository, and a self-hosted
deployment does not get it.

**Things that behave differently for setups that already exist.**

- **A self-hosted edge takes no tokens any more.** It needs `mode: standalone`
  and the coordinator's public key (`coord_pubkey`, or `coord_pubkey_file` where
  the coordinator writes it; `calabi-coord pubkey` prints it), and accepts
  devices by the coordinator's grants, for tunnels and relay alike. A config
  that still lists `accepted_tokens` is refused at start and says why; an empty
  list is ignored, so calabi.net's own edges, whose files carry
  `accepted_tokens: []`, start as before.
- **`tunnels.yaml` no longer names the edge.** `server`, `token`, `token_env`,
  `insecure`, `ca_file`, `trust` and `pins` at the top level are refused in a
  file you wrote, and dropped with a warning from the console's own. Join the
  coordinator — `calabi join`, or a `mesh:` block with a key — and the edge
  comes from it.
- **`calabi http`, `tcp`, `udp` and `sni` in standalone mode** use the device
  this client joined as, and no longer read `CALABI_SERVER`, `CALABI_TOKEN` or
  `CALABI_INSECURE`. A client that has not joined says so.
- **A standalone relay always checks grants**, and needs the coordinator's key.
- **A self-hosted coordinator serves TLS.** One without certificate files used
  to serve plaintext; it now makes a self-signed certificate on its first start
  and keeps it in `./coord-tls` (`CALABI_COORD_TLS_DIR`). Pin its fingerprint on
  the devices (`calabi-coord fingerprint` prints it; invites carry it), or set
  `CALABI_COORD_TLS=off` to stay on plaintext.
- **Removing a key from the coordinator's key file no longer takes its devices
  off.** Devices come back by proving they hold their device key. Disable or
  delete a device to remove it (`calabi-coord device`).
- **A coordinator with a database has no built-in key.** `dev-meshnet-1-key`
  works only on a coordinator with neither a key file nor a database.
- **A connection to your coordinator is never checked against the CA compiled
  into the client**, which is calabi.net's. `ca_file:` is now the only CA
  trusted for it, not one more.

### Your server

- **Added** — **`deploy/server`**: the coordinator and the edge on one machine,
  from one `docker-compose.yml` and one `.env` (the public address, an admin
  token, the tunnel domain). The edge's config is written from the `.env`, the
  coordinator hands the edge its public key over a shared volume and reads the
  edge's certificate itself, and both run with `CALABI_ENV=production`. It runs
  with Docker Compose or `podman compose`.
- **Added** — **The coordinator is released.** Archives for the same seven
  platforms as the client and the edge, `SHA256SUMS.coord`, entries in the build
  manifest, and a docker image, `calabinet/calabi-coord` (amd64, arm64), which
  keeps its certificate, its grant key and — by default — a SQLite database in
  the `/data` volume.
- **Added** — **Grants.** A coordinator without a platform behind it signs a
  grant for each device with a key it creates on first start
  (`./coord-grant.key`, or `CALABI_COORD_RELAY_GRANT_KEY_FILE`).
  `CALABI_COORD_GRANT_PUBKEY_FILE` writes the public half for an edge to read;
  `calabi-coord pubkey` prints it. A grant lasts an hour and devices renew it; a
  disabled or deleted device keeps its tunnels at most until its grant runs out.
- **Added** — **The coordinator names the edge.** `CALABI_COORD_EDGE_ADDR` is
  where devices dial it. Its fingerprint comes from `CALABI_COORD_EDGE_PIN`, or
  the coordinator reads the certificate the edge presents
  (`CALABI_COORD_EDGE_PROBE_ADDR` when it reaches the edge another way) — every
  few seconds until it has one, then every minute — so an edge that replaces its
  certificate is followed by every device without anyone confirming it.
  `CALABI_COORD_EDGE_TRUST=system` is for an edge with a public certificate.
  A device waiting for approval gets no edge.
- **Added** — **Invites.** `calabi-coord invite` prints a `calabi://join` link, a
  QR code, and the same as a `calabi join "…"` command line. By default an
  invite admits one device, for 24 hours; `--uses`, `--reusable`, `--expires`,
  `--no-expiry` and `--tag` change that. `calabi-coord authkey create`, `list`
  and `revoke` manage keys without the link. The coordinator stores only a hash
  of each key.
- **Added** — **`calabi-coord device list | approve | disable | enable |
  delete`**, so managing devices needs no hand-written calls to the admin API.
- **Added** — **The edge keeps its self-signed control certificate** in
  `state.dir` (`control.crt`, `control.key`) when it has no certificate files;
  `calabi-edge -fingerprint` prints the fingerprint. Without a `state.dir` it
  still makes a new certificate at every start, and now warns.
- **Fixed** — **A self-hosted relay crashed a minute after devices used it.** A
  relay with a label and no control plane set up usage reporting with nothing to
  report to, and the first report crashed the process. Relays that report to
  calabi.net (BYOI) were not affected.
- **Fixed** — **A coordinator on SQLite could fail a write with "database is
  locked"** when two writes met; it now waits its turn.
- **Fixed** — **An edge hot-reload could say "applied" and change nothing.**
  Only a fixed list of fields was compared, so a change to any field added
  since — `mode`, `role`, every `relay.*` setting — was logged as applied and
  took effect only at the next restart. A reload that changes anything but
  `base_domain` is now refused, naming the fields, and goes through the same
  steps as start-up.
- **Changed** — (coordinator) Connection records keep the relayed part of each
  hour's bytes; the new columns are added on start. The key file is re-read when
  it changes, every two seconds.

### Tunnels

- **Added** — **`calabi join <invite>`**, the terminal's way onto your server:
  it hands the join to the running daemon, or saves it and starts the daemon.
  `--name`, `--pin`, `--replace`, `--no-start-daemon`.
- **Changed** — **A device signs in to your edge with its coordinator's grant**
  and the proof of its own key, answering a challenge the edge makes for each
  connection. It dials the edge pinned to the fingerprint the coordinator gave,
  and renews the grant on a live session before it runs out.
- **Changed** — `calabi daemon` in standalone mode without `--config` runs the
  console's own `tunnels.yaml` from its data directory instead of exiting with
  "missing --config".
- **Fixed** — **`calabi mesh` commands failed while a `calabi http` ran beside
  the daemon.** A `calabi http`, `tcp`, `udp` or `sni` started while the daemon
  ran recorded its own status page as the daemon's console, and `calabi mesh
  up`, `down` and `status` then went to that page. Only the daemon records its
  console now.
- **Fixed** — `calabi daemon start` looked for the service's console only beside
  the `calabi` binary. It now also looks in the system data directory, where the
  desktop app's service keeps it, and otherwise says that `calabi daemon status`
  will show the address.
- **Fixed** — The status page said the requested port was busy when
  `CALABI_STATUS_ADDR` asked for any port (`…:0`).

### Mesh

- **Added** — **The mesh is a switch, not the sign-in.** Off — in the console,
  or `calabi mesh down` — the device leaves the mesh and keeps its tunnels, and
  stays off across restarts; `calabi mesh up` with no arguments puts it back. A
  daemon reports its tunnels to the coordinator either way.
- **Added** — **A key is only for joining.** A device that has joined comes back
  by proving it holds its device key. A daemon remembers which device it is
  (`mesh-reauth.json` in its data directory), so `auth_key:` can come out of its
  `mesh:` block. A key's expiry and use limit apply to new devices.
- **Added** — **Leaving.** A device that leaves from the phone or the console is
  marked as signed out and needs a new invite to come back. Its record, address
  and seat stay.
- **Added** — **Checking the coordinator's certificate**: `--trust` (`system`,
  `pin`, `ca`, `plaintext`, or `platform` for calabi.net), `--pin` and
  `--ca-file` on `calabi mesh up`, and `trust:`, `pins:`, `ca_file:` in the
  `mesh:` block.
- **Added** — **The relay address is optional.** Without `--relay` a device takes
  its relays from the coordinator's directory.
- **Added** — **Tunnels and traffic on your coordinator.** A daemon that has
  joined reports its tunnels — name, type, addresses, whether each is up, bytes —
  every five minutes and whenever the list changes. The coordinator keeps the
  list and, with a database, tunnel traffic by the hour for 92 days, and gives
  both, with this month's relayed traffic, to the phone and the console.
  calabi.net's coordinator refuses these calls.
- **Fixed** — **A disabled device kept its session.** Every call on a disabled
  device's session is now refused.
- **Fixed** — **Desktop exit devices: relays dialed later went into the mesh.**
  Every relay in the coordinator's directory now keeps the machine's own route,
  including one that appears later.
- **Fixed** — **A device the relay turned away dialed it again every 15
  seconds.** A device deleted on the coordinator, or out of touch with it for
  more than an hour, holds a relay grant that has expired. The relay refused it,
  and the device dialed again on every keepalive sweep for as long as it ran —
  a connection and a warning in the relay's log every 15 seconds. After a
  refusal it now waits longer each time, from 15 seconds up to 5 minutes, and
  keeps asking at that pace. Getting back in touch with the coordinator, waking
  from sleep and a network change each bring an immediate retry. A relay that
  restarts or refuses the connection outright is still retried every 15 seconds.
- **Fixed** — **Right after a device started, reaching another device took about
  five seconds.** The first WireGuard handshake went out before the relay had
  let the device in — before the relay connection was up, or after it was up
  but before the relay had checked the device's grant — and was lost, and
  WireGuard waits five seconds before trying again. Packets now wait, for up to
  three seconds, until the relay admits the device or a direct path is found,
  and go out then. The daemon's log no longer shows `Failed to send handshake
  initiation: use of closed network connection` at start.
- **Changed** — WireGuard's own messages are now part of the daemon's log. They
  used to go to standard output, which a service's log file did not include.

### Local console

- **Added** — **Connect to a self-hosted server**, on the sign-in page and on a
  standalone daemon that has nothing to connect to yet: an invite link, or the
  coordinator's address and a key. The coordinator's certificate is settled
  first — the invite's fingerprint, the system's trusted roots, or a fingerprint
  you compare — and the key is spent last, so a join that stops halfway spends
  nothing. The daemon then starts again in place, on the same port. Signed in to
  calabi.net, it offers to sign out first.
- **Added** — In self-hosted mode: the server in the account menu; a
  *Self-hosted server* card in Settings with the coordinator, the edge this
  device's tunnels run on, and the mesh switch; *Tunnels on this network* and
  *Network traffic this month*; banners when the machine is not connected yet,
  when the coordinator's certificate changed (both fingerprints, and a button
  that trusts only the one presented now), when the device waits for approval,
  needs a new invite, or is disabled. *Disconnect and forget this server* tells
  the coordinator, deletes the console's `tunnels.yaml` — tunnels included,
  counted in the confirmation — and goes back to the calabi.net sign-in page.
- **Added** — A standalone daemon's console saves what the device advertises,
  its routing settings and its declared services into the config.
- **Fixed** — **Not signed in and unable to reach calabi.net, the console showed
  "cannot reach the server" instead of the sign-in page.** A daemon holding no
  credentials now answers "not signed in" itself.

### Mobile

- **Added** — **Join your own server**: *Connect to a self-hosted server* on the
  sign-in page. Scan an invite's QR code, open its `calabi://join` link (a phone
  signed in to calabi.net asks first), or type the address and key. A
  certificate that is neither in the invite nor trusted by the system is shown
  for you to compare with `calabi-coord fingerprint`.
- **Added** — Joined to your own server, the phone shows its devices, the
  tunnels of the desktop daemons, and this month's traffic, also while it is not
  connected. Settings shows the server where the organization was; *Leave this
  server* leaves it. When the server presents another certificate, the phone
  shows both fingerprints and keeps trying with the old one until you trust the
  new one.
- **Added** — **Quick Settings tile.** Settings has a *Quick Settings tile* row:
  on Android 13 and later one system dialog adds it; before that the app shows
  the steps, with separate ones for Huawei and Honor.
- **Changed** — The *Devices* tab is now *Mesh*, beside *Tunnels*.

### On calabi.net

The hosted control plane. **None of this is in this repository**, and a
self-hosted deployment does not get it.

- **Changed** — **Devices come back by proof.** A device reconnecting to the
  mesh proves it holds its device key instead of presenting its sign-in again.
  At that moment the control plane checks that the account is still active and
  a member of the organization, or that the API key is not revoked or expired,
  and refuses it otherwise. Needs a client from this release; older clients
  present their sign-in on every reconnect, as before.
- **Fixed** — In Mesh → Services → Add service, the local address can only be
  this machine (`127.0.0.1` or `localhost`), as the coordinator already
  required. The form said to enter another machine on the LAN, then showed the
  coordinator's error; it now says what is allowed and checks it before sending.
  A device reaches other machines on its LAN through a subnet route.

## 1.12.0 — 2026-09-18

**The first Android app**, and staged rollouts for the automatic update. Client
and edge move together, as always; the edge has no changes of its own.

**What is in this repository and what is not.** Calabi is also a hosted service,
and one release covers both. **Updates**, **Mesh**, **Local console** and
**Mobile** below are changes in what this release ships, built from this tree.
The last section, **On calabi.net**, is the hosted control plane: its code is not
in this repository, and a self-hosted deployment does not get it.

**Two things behave differently for setups that already exist.**

- **A platform daemon now reports how each of its self-updates went** — from and
  to which version, which step failed, the error — to the control plane it is
  signed in to, over the connection it already registers the device on. A
  standalone daemon has no update agent and reports nothing.
- **On calabi.net, a newly advertised subnet route waits for an administrator.**
  Routes that are already working keep working. An organization that wants
  routes to take effect on their own turns off *Routes need approval* under
  Mesh → Settings. A self-hosted coordinator is unchanged: it has no console to
  approve in, so it still approves every route itself, exit routes included.

### Updates

- **Added** — **Staged rollouts.** A release can reach machines over a number of
  hours instead of all at once. Each machine works out from its own install ID
  whether its turn has come, and the local console says so — *being rolled out
  in stages; this machine's turn has not come yet* — with the time its turn is
  expected. *Update now* is not held back, and neither is a machine below the
  minimum supported version. Clients 1.11.x and older do not know about stages
  and install 1.12.0 as soon as they see it.
- **Added** — **Update results** (see above). The daemon records that an update
  started before it launches the installer, so an install that takes the service
  down and never brings it back still shows up — as started, with no result. The
  next process to start reports whether it is the new version. Results that
  cannot be sent yet wait in a local queue of at most 50.
- **Fixed** — **macOS: an automatic update could stop at "Updating" for good.**
  The package let the installer put `Calabi.app` wherever it found another copy
  with the same bundle ID, and on a machine with a second copy the install
  stopped before the service was restarted. The package now always installs to
  `/Applications`. The daemon also waits for the installer it started: if the
  installer exits and the daemon is still the old one, the console reports the
  failure with the installer's last line of output, and a second installer is
  never started while one is running.

### Mesh

- **Fixed** — **Exit devices did not work.** Two route checks each read the
  default route as a claim on the mesh's own address range: from 1.8.0 the
  coordinator dropped a device's `0.0.0.0/0` advertisement when it registered,
  and from 1.9.0 the client dropped the chosen exit device's default route
  before it reached WireGuard. Both now treat `0.0.0.0/0` and `::/0` on their
  own; every other route overlapping the mesh range is still refused. On
  calabi.net the coordinator side is already fixed — a device that already had
  exit-device mode on needs it turned off and on once to advertise again. A
  self-hosted coordinator needs this release.
- **Fixed** — **Linux subnet routers piled up NAT rules across restarts.** A
  router that crashed or was killed, rather than stopped, added its masquerade
  rule again on the next start; one machine had forty identical copies. Rules
  now carry a comment naming the device, and each start removes the ones it left
  behind — including uncommented copies from older versions — before adding its
  own. With nftables every device has its own table, so two clients on one
  machine no longer delete each other's rules. The platform daemon also waits for
  the mesh to shut down, up to 15 seconds, before it exits.
- **Changed** — (coordinator) A device's periodic endpoint report no longer
  pushes a new network map to every peer unless its endpoints or home region
  actually changed. In a mesh of N devices, each one used to receive about N maps
  a minute.

### Local console

- **Changed** — Services are a tab of the Mesh page, beside Devices and Routing,
  as they are in the web console. The old `/services` address redirects.
- **Fixed** — **On a machine with the desktop app installed, `calabi login`
  started a second daemon.** From a terminal without administrator rights it
  could not query the service, took that for "not installed", and started
  another daemon on `:7401` — a second device, joining the mesh as whoever typed
  the command. Not being allowed to query the service now counts as installed:
  login leaves the service alone and says whether it runs on its own sign-in or
  on an API key.
- **Fixed** — `calabi daemon status` in the same terminal printed
  `Access is denied` and exited 1. It now says the service is installed, that
  this shell cannot query its state, and where its console answers.
- **Fixed** — **macOS: `calabi daemon start`, `stop` and `restart` operate the
  service the installer registered** (`com.calabi.daemon`). They looked for a
  service named `calabi` that the installer never creates, and `install` would
  register a second root service over the same data directory. `install` now
  refuses, and `uninstall` prints the removal steps.
- **Fixed** — `calabi logout` said "logged out" when nothing had been: when the
  daemon runs on an API key and refused, when an installed service it cannot see
  was still signed in, and when there was no sign-in at all. It now says what it
  did and did not touch, and exits 1 when refused.
- **Fixed** — The command line and the running daemon no longer spend the same
  refresh token. A refresh token works once; when both refreshed at the same
  moment, the one that lost was signed out.
- **Fixed** — Settings no longer offers *Sign out* on a daemon that runs on an
  API key or in standalone mode, where it failed and the page flashed back as if
  it had worked. On an API key it shows the identity the service runs as, and
  how to change it: reinstall the service with a different key.
- **Fixed** — The desktop tray's *Restart* and *Stop* hints give commands that
  work on that platform — `launchctl` on macOS, `Restart-Service` and
  `Stop-Service` in an administrator PowerShell on Windows — instead of
  `sudo calabi daemon restart`, which neither installer puts on the PATH.

### Mobile

**Calabi for Android, first release.** It makes a phone a device in your
organization's mesh. It signs in to calabi.net; it does not join a self-hosted
coordinator. Android 8.0 or later, 64-bit and 32-bit ARM, in English and
Simplified Chinese.

It is not on Google Play: `calabi-android.apk` is on the download page, and
Android warns before installing an app from outside the store. It does not
update itself — a newer APK installs over it. The certificate it is signed with
is printed on the releases page, to check before installing.

- **Mesh device** — connect and disconnect in the app or from a Quick Settings
  tile, and see the organization's devices and whether each is reached directly
  or through a relay. After Wi-Fi drops, the mesh is back within about two
  seconds of the network returning.
- **Exit device** — send all of the phone's traffic out through a device in
  your mesh. Other mesh devices stay on direct connections meanwhile.
- **Connect at startup** — off by default.
- **Background running** — some Android builds stop background apps, VPN
  included, a while after the screen goes off. When the app finds it was stopped
  that way it says so and opens the vendor's page for allowing background
  activity (Huawei, Honor, Xiaomi); on other phones it asks to be exempt from
  battery optimization.
- **Tunnels, read-only** — the tunnels you can see in the organization, with
  their public addresses to copy, share or open, and access records for the last
  24 hours or 7 days. The phone does not serve tunnels.
- **Usage** — this month's traffic against the plan's limit, the last seven
  days, and mesh device seats.
- **Replace an old device** — reinstalling the app creates a new mesh key, so
  the phone joins as a new device. The app offers to remove your own offline
  device of the same platform and take over its name.

### On calabi.net

The hosted control plane. **None of this is in this repository**, and a
self-hosted deployment does not get it.

- **Added** — **An organization update policy**, under Clients → Update policy.
  Administrators can require the organization's machines to install at least
  security updates, or everything, automatically, and cap how many days a
  machine may hold an update back. It only tightens: each machine follows
  whichever of its own setting and the organization's is stricter, and gets its
  own choice back when the policy is removed. It needs a 1.12.0 client, whose
  local console shows the setting in effect and greys out what the organization
  does not allow.
- **Added** — The client list marks a machine whose last update failed, and the
  client's details show its most recent update.
- **Changed** — **New subnet routes wait for an administrator** (see the top of
  this release). The switch is *Routes need approval* under Mesh → Settings; an
  exit device always needs approval.
- **Changed** — In Mesh → Devices, a device offering to be an exit device shows
  one *Exit device* tag — green when approved, orange when waiting — which an
  administrator clicks to approve or revoke.
- **Fixed** — Turning off mesh connection records did not stay off: the stored
  records were deleted once, recording carried on, and the switch showed as on
  after a refresh. An organization that turned them off before this fix needs to
  turn them off again.
- **Fixed** — Saving one mesh setting could switch another back — device
  approval, connection records, route approval.
- **Fixed** — A member could read a colleague's tunnel by its ID through the API
  although the list hid it. They now get the same "not found" as for a tunnel
  that does not exist.
- **Fixed** — Typing the two-step verification code through an input method put
  each digit into two boxes.
- **Changed** — The sign-in page shows a preview of the console beside the form.
- **Added** — The download page offers the Android app, and the version number
  links to that release's notes.

## 1.11.1 — 2026-09-16

A fix release for the automatic update 1.11.0 introduced. Client and edge move
together, as always; the edge has no changes of its own.

### Updates

- **Fixed** — **On Windows, an automatic update reported success and replaced
  nothing.** The installer overwrote the daemon's executable while the service
  was still running it. Windows does not allow that, and a silent install does
  not fail on it: it skips the file, exits successfully, and records the new
  version in Apps & features. The desktop shell was updated, the daemon was not,
  and the next restart tried again. The installer now stops the service and
  waits until the file is actually released before copying — and if it cannot,
  it restarts the service and refuses, rather than skipping the file. Verified
  on a running service: the daemon is replaced and the service is back within
  two seconds.
- **Fixed** — **A client installed some other way was handed the desktop
  installer.** A Windows client installed with scoop or from a zip and running
  as a service received the desktop installer: the machine gained a desktop app
  while its daemon stayed at the old version. A Homebrew install on macOS was
  handed the .pkg the same way. Such an install now says that it updates the way
  it was installed — `scoop update calabi`, `brew upgrade calabi`, or a new
  archive — in the local console and in `calabi update`, and never runs the
  installer. The Windows installer also refuses to take over a Calabi service it
  did not create, which protects machines still running an older client.

### On calabi.net

The hosted control plane. **None of this is in this repository**, and a
self-hosted deployment does not get it.

- **Added** — The download page offers the macOS desktop package, and a GitHub
  download link beside every file.
- **Fixed** — Actions inside a drawer no longer open a second dialog on top of
  it: creating a tunnel for a client that is offline, and reopening a support
  ticket, now ask in place.

## 1.11.0 — 2026-09-16

**A client that knows when it is out of date.** Until this release the only
machines that ever learned a newer version existed were the ones somebody
happened to open a console on; a server installed once and left alone could sit
six versions behind with nothing anywhere saying so. Every daemon now checks,
says so where you will see it, and — where it is allowed to — installs it on a
schedule you choose. Client and edge move together, as always.

**What is in this repository and what is not.** Calabi is also a hosted service,
and one release covers both. **Updates**, **Tunnels** and **Local console** below
are changes in the binaries attached to this release, built from this tree. The
last section, **On calabi.net**, is the hosted control plane: its code is not in
this repository, and a self-hosted deployment does not get it.

**Two things behave differently for setups that already exist.**

- **Every daemon now makes one request every six hours** to
  `download.calabi.net`, to read a signed list of published versions. It
  downloads and installs nothing. Setting `CALABI_UPDATE_MANIFEST` to an empty
  value turns the check off entirely.
- **A daemon running as a privileged system service can now replace itself.**
  What it does unasked is a setting on that machine, which starts at *automatic*
  on Windows and macOS and at *security updates only* on Linux — a Linux daemon
  is usually a server, and a server should not restart itself for a routine
  release. A daemon that is **not** a privileged service never installs
  anything: it reports and waits for you.

### Updates

- **Added** — **Every daemon checks; only a privileged service installs.** These
  are two different permissions and they are now two different answers. A daemon
  that cannot install says which of the reasons applies — nothing was published
  for this platform, this install is not a system service, the manifest is
  malformed — instead of failing a check every six hours and telling nobody.
- **Added** — **A per-machine setting**, in the local console under Settings:
  *automatic*, *security updates only*, or *notify me*. Under *automatic* an
  update waits for a maintenance window (03:00–05:00 by default, on the
  machine's clock) and waits again while traffic is still moving through the
  client — with a backstop, seven days by default, after which it stops waiting.
  A laptop that is closed every night and a server that is busy every night both
  still land the update.
- **Added** — **Security releases skip the waiting rules** but do not override
  *notify me*. A release below the publisher's minimum supported version
  overrides even that, and the console says so plainly rather than letting the
  restart be a surprise.
- **Added** — **`calabi update` and `calabi update --check`**, for the machines
  that never have a console open. They drive the running daemon rather than
  doing the work themselves, so there is exactly one set of signature checks in
  front of the installer.
- **Added** — **Linux installs in place** — the new binary is unpacked, run once
  to prove it works, swapped in, and the service is restarted. Windows and macOS
  run their own installers, as before.
- **Added** — **The version list is signed as a whole.** One signature covers the
  version, every platform's installer URL, its SHA-256 and its own signature, so
  a manifest cannot be edited to point a privileged service at a different file.
  A daemon also refuses a manifest offering a version older than one it has
  already seen, unless the publisher marked it a deliberate rollback — replaying
  a genuinely signed older release is a downgrade that needs no key.
- **Changed** — The local console's Settings page: updates are their own card,
  and the account card is gone — the organization you are serving now appears in
  the account menu, where the rest of your identity already was.

### Tunnels

- **Fixed** — **`calabi http 8080` works in an official build.** One-shot
  commands never looked for an edge; they used a default address that release
  builds deliberately leave empty, so the first command in the documentation
  failed for everyone who had not also installed the service. They now find an
  edge the same way the daemon does, and they honour `CALABI_EDGE_AFFINITY`, so
  an organization with its own edges does not silently land on the platform.
- **Fixed** — Restarting a self-hosted edge no longer takes the command line down
  with it. The edge a client is anchored to is a preference, not a wall.
- **Fixed** — A one-shot command no longer serves the full dashboard page, which
  had no API behind it, and no longer counts tunnels pushed from the control
  plane as its own — which is why its own tunnel appeared twice.
- **Fixed** — A tunnel created from the command line now registers the device,
  like every other way of creating one.
- **Fixed** — A tunnel whose upstream has never been probed is no longer reported
  as healthy.
- **Fixed** — (edge) A subdomain sequence that rolled backwards could land on a
  row belonging to another organization, and the edge claimed it.

### Local console

- **Fixed** — `login` and `logout` now tell the running daemon. Signing out used
  to delete the credentials file while the daemon kept serving the old session.
- **Fixed** — The address the console prints is where it is listening now, not a
  pointer left behind by a previous start; and when it is not on `:7400` —
  which is normal with a second client on the machine — the CLI says where it
  is instead of looking broken.
- **Fixed** — `--standalone` survives `daemon install`. The service came back
  wired to the platform, quietly undoing the choice.
- **Fixed** — The overview's tunnel card showed the organization's quota rather
  than the one that applies to you, and the relay figure had quietly become a
  local measurement while its label still said otherwise.

### On calabi.net

The hosted control plane. **None of this is in this repository**, and a
self-hosted deployment does not get it.

- **Fixed** — The same account saw traffic figures three orders of magnitude
  apart depending on whether it was the web console or an agent asking. Traffic
  is one figure for the whole organization, for every member — the narrower
  answer does not exist, because relayed bytes are recorded between devices and
  can never be attributed to a person. Per-member *quotas* are unaffected; those
  are still per member.
- **Fixed** — The monthly-traffic card said "0" for organizations serving from
  their own edges.
- **Changed** — A tunnel's **Settings** tab is administrators only. Mesh
  connection records are now visible to auditors, and members can see the
  records for their own devices.
- **Changed** — Creating and editing a tunnel, and adding a self-hosted node,
  are drawers rather than full pages.
- **Added** — A tunnel records **which door it was created from** — command
  line, local console, web console or API key — shown in the admin console.

## 1.10.0 — 2026-09-14

The largest release since the mesh shipped, and most of it answers one question
asked twice: **who may reach this, and can you find out afterwards who did.**
Client and edge move together, as always.

**What is in this repository and what is not.** Calabi is also a hosted service,
and one release covers both. **Tunnels**, **Mesh** and **Local console** below
are changes in the binaries attached to this release, built from this tree. The
last section, **On calabi.net**, is the hosted control plane: it changes what
calabi.net users see, its code is not in this repository, and a self-hosted
deployment does not get it. It is listed because the same binaries serve both —
not as something you will find here.

**Three things behave differently for setups that already exist.** All three are
on calabi.net.

- An IP allow list of `0.0.0.0/0` no longer counts as access protection, and
  neither does a deny list on its own. If your organization requires protection,
  tunnels configured that way now appear in the violations list. Nothing that is
  running is stopped.
- `--ip-allow` and `--ip-deny` now take effect. The client always sent them; they
  used to be accepted, noted as self-hosted-only, and discarded. A tunnel started
  with them is now really restricted by them.
- **Upgrade your self-hosted edges along with the client.** An edge older than
  1.10.0 does not understand a tunnel that references an organization's sign-in
  application, and serves that tunnel **with no sign-in at all** rather than
  refusing. Older edges also collect no access records.

### Tunnels

- **Added** — **A per-visitor rate limit** (`per_ip_per_minute`) beside the
  existing per-tunnel one. A single cap shared by all visitors is also the lever
  an abuser pulls to take the tunnel down for everyone; the two now apply
  together, and the existing setting still means exactly what it meant before.
- **Changed** — **Every refusal the edge serves now looks the same.** Being
  turned away by a password prompt, by a sign-in that was declined, or by a
  sign-in that did not complete used to produce a bare line of internal text
  with nothing to quote at support, while an IP refusal produced a proper page.
  All of them now carry the same page, a `CAL-xxxx` code and a warning mark —
  and none of them tell a stranger anything about the organization's account.
- **Fixed** — The client now reports whether the edge **applied** the security
  flags it was given, instead of inferring it from its own `--standalone`
  setting. An edge wired to a control plane does not apply them, which the client
  had no way to detect: `--basic-auth` went nowhere, every console correctly
  showed no protection, and the warning that would have said so was suppressed by
  the very flag that made it wrong.
- **Fixed** — Two ways the edge's port pool disagreed with the tunnels that
  actually exist. At startup the pool was empty, so the first claim could hand
  out a port a live tunnel held — and the loser was deleted. And a port
  persisted during a session was not marked as taken, so the same number was
  offered again and the claim was refused with "remote port already bound",
  leaving a tunnel waiting for a client that was already connected. Ports are
  now reserved when the tunnel is persisted and released when it is deleted.

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
  when the coordinator is unreachable and in the many networks that never wrote
  a rule at all, and it outranks any rule that would have allowed the
  connection. Replies on connections the machine itself started still arrive.
- **Added** — **Connection records.** Which device talked to which, in which
  hour, how many bytes, and whether it went direct or through a relay. No
  endpoint addresses and no public IPs are in it — the location trail those
  would form is exactly what the mesh deliberately does not keep. The
  coordinator holds them and enforces the retention period. They are reported by
  the clients themselves, which the console says plainly: this is evidence, not
  proof, and it is never an input to an authorization decision.
- **Added** — Devices report their operating system; the peer list shows the
  machine name instead of a public key, says which services a device offers, and
  can be filtered by name, address or service.
- **Added** — A device waiting for approval is told so, and a client that cannot
  connect can say why.

### Local console

- **Fixed** — The console occasionally bounced to its login screen, and opening a
  new tab worked. Two parts of the daemon refreshed the sign-in at the same time
  and one of them was told to sign in again; every part now shares one refresh.
- **Changed** — The tunnel pages were rebuilt: creating one is a series of steps
  rather than one long form, and the protocol is shown as a badge.

### On calabi.net

The hosted control plane. **None of this is in this repository**, and a
self-hosted deployment does not get it — it is here because the same binaries
serve both, and because two of these change what an already-running tunnel does.

- **Added** — **Access records.** Per tunnel and per hour: which visitor
  addresses connected and how each connection ended. Off by default, enabled per
  organization, with a retention period you choose. These are connections, not
  requests: one keep-alive connection carrying fifty requests is one row.
  Request lines, paths, headers and user agents are not recorded — that is the
  local console's job, on your own machine. A tunnel being scanned cannot make
  the table grow without bound: at most 256 distinct addresses per tunnel per
  hour are listed individually, and the rest are counted together. The edge-side
  collection ships in `calabi-edge`; everything that stores, keeps or reads them
  does not.
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
- **Added** — **Offline notification**, per tunnel and off by default. A tunnel
  that stops serving can email you instead of waiting for somebody to hit a 502.
  Ten minutes of grace, so a reconnect or a deploy does not trigger it, and one
  message per outage rather than one per report.
- **Added** — Tunnels can be **disabled automatically after N days with no
  visitor**. This is the only setting here that touches something already
  running, so it acts only when it can tell "nobody used it" apart from "we were
  not watching": access records must be on, and must have been on long enough.
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
- **Added** — **Members can manage their own devices** — rename, disable, delete
  — instead of looking at a page of greyed-out buttons. The thirteen actions
  that decide how the *network* behaves (approvals, tags, routes, rules, relays,
  services) stay with administrators. A device carrying a tag belongs to the
  organization rather than to a person — a gap that also left a hole in this
  rule, now closed — and a device publishing an approved route cannot be deleted
  by its owner until the route is withdrawn.
- **Changed** — Removing a member now **disables the mesh devices in their
  name**, stops their tunnels and revokes the API keys they minted, before the
  membership goes. Until now a removed member's connected daemon kept serving on
  the organization's domain, their keys kept managing its tunnels, and a laptop
  that never disconnected stayed inside the private network indefinitely — the
  console door closed, the data plane's did not. Tagged devices and tunnels
  running on an organization agent are left alone: stopping a CI runner because
  whoever installed it left is an incident, not offboarding.
- **Changed** — Switching organizations ends the session you switched away from.
- **Fixed** — A tunnel that has not been claimed no longer has its configuration
  broadcast to every edge, self-hosted edges included.
- **Fixed** — An installed agent never reported whether it could reach the
  service it forwards to. The console showed such tunnels as online while the
  local probe had been failing since the agent started; only interactive
  sessions reported. Agents carry their credential in the environment, and the
  health reporter was the one code path that looked only in the credentials
  file.
- **Changed** — The edge reports its own version, so the consoles can show what
  each edge is running.

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
