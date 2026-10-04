# Changelog

## [0.1.0]

- First public backend. Sigma YAML to a libsigma `.sigmac` v5 artifact
  and `rules.corr.json` version 1.
- Optional ECS rename for taxonomy `sigma`. Taxonomy `ecs` and
  `--no-ecs` compile field names as written.
- No deployment field allowlist. Callers drop rules they cannot match.
