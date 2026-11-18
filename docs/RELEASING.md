# Releasing

How to cut a release: bump the version, update the changelog, merge,
tag, and let CI publish it. Tagging is the only step a human has to
do by hand.

## 1. Decide the version

`MAJOR.MINOR.PATCH`, stored in `pyproject.toml` `project.version`.

- A `.sigmac` layout change (`Contract: format`) or a correlation
  schema change (`Contract: corr`) is a libsigma contract first. This
  package follows that version. Bump MAJOR when the emitted bytes are
  not readable by the libsigma this release claims.
- New, backward-compatible compilation -> bump MINOR.
- Bug fixes only -> bump PATCH.

## 2. Update the changelog

Add a `## [MAJOR.MINOR.PATCH]` section to `CHANGELOG.md`. The release
workflow copies that section into the GitHub release body. The match
is the prefix `## [MAJOR.MINOR.PATCH]`.

## 3. PR it, merge to main

Same as any other change: a work branch, commits that each pass
`scripts/check-commit-msg.sh`, CI green, then squash or rebase into
`main`.

## 4. Tag and push

The tag points at the commit whose `pyproject.toml` version equals
the tag. The workflow rejects a mismatch.

```
git tag MAJOR.MINOR.PATCH
git push origin MAJOR.MINOR.PATCH
```

The tag matches `[0-9]+.[0-9]+.[0-9]+`. No `v` prefix. Tags are not
rewritten (`docs/BRANCHES.md`).

## What happens automatically

Pushing the tag fires `.github/workflows/release.yml`:

1. `pytest`, then `python -m build`, then `twine check --strict`.
2. Trusted publishing uploads `dist/*` to PyPI. No API token is
   stored in the repository.
3. A GitHub Release is published with those files and the changelog
   section as the body.
