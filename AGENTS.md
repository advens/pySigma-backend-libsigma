# AGENTS.md

pySigma backend. Sigma YAML in, one `.sigmac` format 5 artifact and
`rules.corr.json` schema 1 out. The matcher stays in libsigma.

Read `docs/COMMIT.md` and `docs/BRANCHES.md` before any
commit-shaped or branch-shaped output. You do not commit, push,
or tag. The human does, using those contracts. Work branches are
`<type>/<scope>-<slug>`. Never push `main`.

## Build and test

```
python -m pip install -e '.[dev]'
python -m pytest -q
```

Python 3.11 or newer. Dependency `pysigma>=1.3,<3`.

## In

`src/sigma/backends/libsigma/`, `src/sigma/pipelines/libsigma/`,
`tests/`, `docs/`, `README.md`, `CHANGELOG.md`, `pyproject.toml`.

## Not in

The C matcher. A `.sigmac` layout change or a correlation schema
change is a libsigma contract. This package emits the bytes libsigma
already specified.

## Must

- One write set. If the task needs a file outside it, stop.
- Paste the command and its output. Do not claim tests passed without
  that paste.
- `Contract: format` or `Contract: corr` is a human decision.

## Never

- `git commit`, `git push`, `git tag`, `git rebase`, merge, force-push
- Rewrite `docs/COMMIT.md`, `.githooks/`, `scripts/check-commit-msg.sh`,
  `.github/workflows/`, or `CODEOWNERS` unless that is the write set
- Assistant attribution in comments, commits, or docs
- Em-dashes in anything that ships
