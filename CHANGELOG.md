# Changelog

## [0.1.1]

PATCH: two value types no longer drop the rule. No `.sigmac` or
`rules.corr.json` change.

- A boolean value (`Signed: true`) compiles to a case-insensitive
  equality on `true` or `false`. It used to drop the rule with
  "unsupported value type SigmaBool".
- A fieldless `|re` keyword compiles to a regex over `event.original`,
  case-sensitive unless `|i`. It used to drop the rule.

## [0.1.0]

- First public backend. Sigma YAML to a libsigma `.sigmac` v5 artifact
  and `rules.corr.json` version 1.
- Optional ECS rename for taxonomy `sigma`. Taxonomy `ecs` and
  `--no-ecs` compile field names as written.
- The rename tables are also the pySigma pipeline `libsigma_ecs`.
- No deployment field allowlist. Callers drop rules they cannot match.
- Supports pySigma 1.3 and later 1.x, and 2.x. CI runs both lines.
