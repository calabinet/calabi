# Contributing

Thanks for your interest in contributing! This is the open-source data plane
(edge + client) of Calabi, released under **Apache-2.0** (see `LICENSE`).

## Developer Certificate of Origin (DCO)

We use the [Developer Certificate of Origin](DCO) (DCO 1.1) — **not** a CLA.
It's a lightweight, one-line-per-commit certification that you have the right to
submit your contribution under this project's license.

Every commit must be **signed off**. Adding a sign-off is one flag:

```bash
git commit -s -m "your message"
```

That appends a line to the commit message:

```
Signed-off-by: Your Name <you@example.com>
```

By signing off you certify the [DCO](DCO) (you wrote the code, or otherwise have
the right to submit it under Apache-2.0). The name/email must be real and match
the commit author.

> Why a sign-off? The code in this repository is the same data plane that powers
> Calabi's hosted product — not a stripped-down copy of it. The DCO is how every
> contributor confirms they have the right to contribute the code, which keeps
> that shared core clean for everyone, self-hosted and hosted alike.

### Fixing a missing sign-off

If CI flags a commit without a sign-off:

```bash
# last commit:
git commit --amend -s --no-edit && git push --force-with-lease

# multiple commits on your branch (replace main with your base):
git rebase --signoff main && git push --force-with-lease
```

A CI check (`.github/workflows/dco.yml`) verifies every commit in a pull request
is signed off.

## Pull requests

- Keep changes focused; one logical change per PR.
- Run `make build` and `make verify` before pushing.
- Match the surrounding code style.
- Describe what changed and why in the PR description.

## Reporting issues

Please include your OS/arch, the `calabi` / `calabi-edge` / `calabi-coord`
version (`calabi version`), whether you are self-hosting or on the hosted
platform, and steps to reproduce.
