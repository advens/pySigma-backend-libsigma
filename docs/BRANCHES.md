# Branch policy

`main` is the only long-lived branch. Everything else is a short-lived work
branch that dies at merge.

## main

- CI on `main` is green (`commit-msg`, `test`).
- No merge commits. Squash or rebase only.
- Squash uses the PR title as the subject and the PR body as Why / Proof /
  Contract (`docs/COMMIT.md`).
- The head branch is deleted on merge.
- Force-push and deletion of `main` are forbidden.

## Work branches

Name:

```
<type>/<scope>-<slug>
```

`<type>` and `<scope>` are the same closed lists as `docs/COMMIT.md`.
`<slug>` is lowercase ASCII, hyphens, at most 40 characters.

Examples: `fix/backend-placeholder`, `feat/pipeline-dns-answer`.

One branch, one PR, one concern.

## Tags

`N.N.N` is a human release. Tags are not rewritten.
