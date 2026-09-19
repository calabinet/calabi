# Contributing

This repository is the open-source part of Calabi — the client, the edge, the
coordinator and the Android app — under **Apache-2.0** (see `LICENSE`).
Contributions are welcome.

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
- Run `make build` and `make verify` before pushing.
- Match the surrounding code style.
- Describe what changed and why.

## Reporting issues

Include your OS and architecture, the version (`calabi version`, and
`calabi-edge` / `calabi-coord` if they are involved), whether you run your own
server or use calabi.net, and the steps to reproduce.
