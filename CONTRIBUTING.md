# Contributing

## Commits

`docs/COMMIT.md` is the contract. It is not optional. Install the
hook before you commit:

```
git config core.hooksPath .githooks
git config commit.template .gitmessage
```

PRs squash-merge. The PR title is the subject. The PR body is Why /
Proof / Contract. CI runs `scripts/check-commit-msg.sh` on every
commit in the PR and on the squash on `main`. GitHub's squash
` (#<n>)` suffix is not part of the 72-character subject.

## Branches

`docs/BRANCHES.md`. Work branches are `<type>/<scope>-<slug>` with
the same type and scope lists as commits. `main` is not a work
branch.

## Issues

Use the Bug form. Security reports go to jeremie.jourdin@advens.fr,
not the tracker.

## Code

Python 3.11+, type hints on new public functions. `python -m pytest`
before you ask for merge.

The `.sigmac` byte layout and the `rules.corr.json` schema are owned
by libsigma. A change to either lands there first (`Contract: format`
or `Contract: corr` in that repository). This backend follows the
published header.

## Releasing

Set `version` in `pyproject.toml`, add the `CHANGELOG.md` section,
then tag `N.N.N` on `main`. The release workflow refuses a tag that
differs from `version`. It runs the tests, builds an sdist and a
wheel, publishes them to PyPI, then attaches them to the GitHub
release.

PyPI publishing uses trusted publishing from the `pypi` environment.
There is no API token in the repository settings. The PyPI project
trusts owner `advens`, repository `pySigma-backend-libsigma`,
workflow `release.yml`, environment `pypi`.
