# Contributing

This repository is the open-source part of Calabi — the client, the edge, the
coordinator and the Android app — under **Apache-2.0** (see `LICENSE`).
Contributions are welcome.

To build and run the three programs against each other on one machine, see
**[DEVELOPMENT.md](DEVELOPMENT.md)**. To report a vulnerability, see
**[SECURITY.md](SECURITY.md)** — not a public issue. Taking part here means
following the **[Code of Conduct](CODE_OF_CONDUCT.md)**.

## How this repository is updated

Development happens in a private monorepo that also holds Calabi's
control-plane services. This repository is a **one-way mirror** of the
open-source part of it, refreshed by a sync commit each release.

That does not stop your pull request from landing. It changes what you see when
it does:

1. Your pull request is read and reviewed **here**.
2. Once it is accepted, a maintainer applies your commits upstream, **keeping
   you as the author**. Your name stays on the commit.
3. The next sync brings them into this repository, and your pull request is
   closed with a link to the commit that carries your change.
4. The change is credited to you in `CHANGELOG.md`.

So an accepted pull request shows as **closed**, not merged. GitHub has no
other way to say this. It is not a rejection — a rejection says so, in words.

The same applies to files: everything here is generated from upstream, so a fix
to a comment, a README or a workflow is made through a pull request like any
other, never by editing the mirror.

## What belongs here

**Accepted:**

- Bug fixes in the client, the edge, the coordinator or the Android app.
- Support for a platform we do not test: a BSD, an architecture, a distribution
  with its own service manager, an unusual NAT or corporate proxy.
- Packaging: Homebrew, Scoop, AUR, nixpkgs, `.deb`/`.rpm`, container recipes.
- Self-hosting recipes: compose files, systemd units, Kubernetes manifests.
- Tests, especially one that reproduces a bug you are fixing.
- Corrections to the documentation in this repository. If a doc disagrees with
  the code, the doc is the bug.

**Not accepted here:**

- **Control-plane features** — organizations, billing, quotas, member approval,
  the web console. That code is not in this repository, so there is nothing
  here to change.
- **Wire-protocol or coordinator-contract changes** without an issue first. A
  client, an edge and a coordinator from different releases have to keep
  talking to each other; that constraint decides the shape of the change before
  the code does.
- **Anything that changes the released binaries' bytes for no functional
  reason** — build flags, embedded metadata, dependency bumps done for their own
  sake. Every release is reproducible from this tree, and a byte change that
  buys nothing costs that.
- **Sweeps**: renaming, reformatting, restructuring or "modernizing" across
  files. They conflict with everything in flight and are hard to review.
- **New dependencies**, unless the pull request says why the standard library
  and the existing ones will not do. The client runs as a privileged service on
  other people's machines.

For anything large, open an issue first and let's agree on the shape. That is
about not wasting your weekend, not about permission.

## Sign off every commit (DCO)

Every commit needs a sign-off under the [Developer Certificate of Origin](DCO)
(DCO 1.1). There is no CLA. The sign-off certifies that you wrote the change, or
otherwise have the right to submit it under Apache-2.0.

```bash
git commit -s -m "your message"
```

That adds this line to the commit message:

```
Signed-off-by: Your Name <you@example.com>
```

Use your real name and email, matching the commit author. A CI check
(`.github/workflows/dco.yml`) verifies every commit in a pull request.

### Adding a missing sign-off

```bash
# the last commit:
git commit --amend -s --no-edit && git push --force-with-lease

# several commits on your branch (replace main with your base):
git rebase --signoff main && git push --force-with-lease
```

## Pull requests

- One logical change per pull request.
- Run `make build` and `make verify` before pushing. CI
  (`.github/workflows/ci.yml`) builds, vets and tests every module on Linux,
  macOS and Windows.
- Add a test for a bug fix. Make it fail without your fix — a test that passes
  either way is worse than none.
- Match the surrounding code style. `gofmt` is checked by CI.
- Describe what changed and why. If it fixes an issue, link it.

## Reporting issues

Include your OS and architecture, the version (`calabi version`, and
`calabi-edge` / `calabi-coord` if they are involved), whether you run your own
server or use calabi.net, and the steps to reproduce.

Quote log lines in full. The exact wording is what we search for, and it tells
us which build you are running.

## Questions

### Why is the monorepo private?

It holds the control-plane services that run calabi.net — the part that is not
open source. The client, the edge and the coordinator are published whole, and
the official binaries are built from this tree, not from a separate one. See
[the README](README.md#releases-and-checking-them-yourself).

### Can I run a coordinator without calabi.net?

Yes, that is what `calabi-coord` is. It is the same coordinator, and
`pkg/hooks-proto` is the interface it uses to reach an identity, quota and
billing system — yours, if you implement those three services (six RPCs). See
[docs/self-hosting.md](docs/self-hosting.md).

### My pull request has been open for a while.

Ping it. A quiet pull request usually means it needs a maintainer with context
on that component, not that it was dismissed.
