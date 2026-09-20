# Security policy

Report a vulnerability privately. Do not open a public issue for one.

## Reporting

Use either:

- **GitHub** — the **Security** tab of this repository → **Report a
  vulnerability**. This opens a private thread with the maintainers.
- **Email** — [security@calabi.net](mailto:security@calabi.net).

Both reach the same people. GitHub is preferred: the thread carries the fix and
the advisory all the way to publication.

## What to include

- What the flaw is, and what an attacker gets from it.
- Which component: the client (`calabi`), the edge (`calabi-edge`), the
  coordinator (`calabi-coord`), or the Android app.
- The version (`calabi version`, `calabi-edge -version`, `calabi-coord
  -version`) or the commit.
- Whether it applies to a self-hosted server, to `calabi.net`, or to both.
- Steps to reproduce, and a proof of concept if you have one.

## What happens next

1. **Within 3 working days** — we confirm we received the report and say
   whether we can reproduce it.
2. **Within 10 working days** — we tell you our assessment: severity, whether
   we treat it as a vulnerability, and a target date.
3. **The fix** ships in a release. Anything exploitable against a default
   configuration is published as a GitHub Security Advisory with a CVE, and is
   marked `critical` in the update manifest so clients offer it immediately.
4. **Credit** goes to you in the advisory and the changelog, under whatever
   name you give us. Tell us if you would rather not be named.

We publish the reproducer **with** the fix, never before it — a working
reproducer for an unpatched release is an exploit, and self-hosted servers
update on their own schedule.

We do not run a paid bug bounty.

## Scope

**In scope** — everything in this repository: the client and its local console,
the edge, the coordinator, the Android app, and the release artifacts and their
signatures.

**Also in scope** — the hosted platform at `calabi.net`, `console.calabi.net`,
`*.calabi.online` and `download.calabi.net`. Its server code is not in this
repository, but report it the same way.

**Out of scope** — reports with no security impact: missing hardening headers
with no exploit path, output from an automated scanner with nothing behind it,
rate limiting on unauthenticated endpoints, self-XSS, and anything that needs
an attacker to already have root on the victim's machine.

Please do not test against other people's servers or tunnels. A self-hosted
server of your own ([DEVELOPMENT.md](DEVELOPMENT.md) or
[docs/self-hosting.md](docs/self-hosting.md)) is the right place.

## Supported versions

The latest release. Fixes go into the next release from `main`; we do not
backport to older lines.

## Questions

### Why not open a public issue?

Self-hosted servers decide for themselves when to update, so a public report
leaves every one of them exposed until its operator acts. A private thread lets
the fix and the release land first.

### What if the flaw is in a dependency?

Report it to us anyway if it is reachable through one of these programs. We
will handle the upgrade and coordinate with the upstream project.
