# pySigma-backend-libsigma

pySigma backend that compiles Sigma YAML to a [libsigma](https://github.com/advens/libsigma) ruleset.

The matcher never parses YAML. This package writes two files:

| File | What it is |
|------|------------|
| `rules.sigmac` | One binary artifact for the whole collection. Format version 5, as specified in libsigma `src/docs/SIGMAC_FORMAT.md`. |
| `rules.corr.json` | Correlation rules (`event_count`, `value_count`, `temporal`, `temporal_ordered`, the numeric aggregations, and the beaconing extension). Schema version 1, as loaded by libsigma `corr_format.h`. |

License: LGPL-2.1-only, the same grant as pySigma (`License-Expression: LGPL-2.1-only`) and the SigmaHQ backends. This package subclasses `sigma.conversion.base.Backend`. libsigma stays Apache-2.0. The serializer is the reference emitter from libsigma (`src/reference/sigmac/format.py`); the copyright holder publishes this copy under LGPL-2.1-only with the backend. The copy in the libsigma repository stays Apache-2.0.

```
pip install pySigma-backend-libsigma
libsigma-sigmac rules/ -o rules.sigmac --corr rules.corr.json
```

From Python:

```python
from sigma.collection import SigmaCollection
from sigma.backends.libsigma import LibsigmaBackend

backend = LibsigmaBackend()
collection = SigmaCollection.from_yaml(open("rule.yml").read())
open("rules.sigmac", "wb").write(backend.convert(collection, "sigmac"))
open("rules.corr.json", "w").write(backend.convert(collection, "corr"))
```

`sigma convert -t libsigma` calls the same `convert()`. The `.sigmac` result is bytes. Write it from `libsigma-sigmac` or from the snippet above. `-f corr` is text.

`convert()` keeps the full `CompileResult` on `backend.last_result` (`errors`, `dropped`, `warnings`, `sidecar`).

## ECS rename

libsigma compares field names as strings. It does not know ECS, Sysmon, or Zeek. If the rule says `Image` and the event callback returns `process.executable`, the rule does not match.

SigmaHQ rules are written in the Sigma taxonomy. The field is `Image`, `CommandLine`, `src_ip`, `QueryName`, `User`. A collector that parsed the event into ECS has `process.executable`, `process.command_line`, `source.ip`, `dns.question.name`, `user.name`.

Those are two different steps, and only the first one lives here.

**Rename.** With `ecs=True` (the default), a rule whose taxonomy is `sigma` or absent is run through `ecs_pipeline()` before it is compiled. The pipeline is a logsource-gated table:

| Rule logsource | Sigma name | Name written into `.sigmac` |
|----------------|------------|-----------------------------|
| `category: process_creation` | `Image` | `process.executable` |
| `category: process_creation` | `CommandLine` | `process.command_line` |
| `category: firewall` | `src_ip` | `source.ip` |
| `category: dns` or `dns_query` | `QueryName`, `query` | `dns.question.name` |
| `service: sshd` | `User` | `user.name` |

A rule marked `taxonomy: ecs` is already written with the names the callback returns, so the table is not applied. `Image` in an `ecs` rule stays `Image`. `libsigma-sigmac --no-ecs` (or `LibsigmaBackend(ecs=False)`) does the same for every rule: the name in the YAML is the name in the artifact.

The same tables are installed as the pySigma pipeline `ecs` (`sigma.pipelines.libsigma`) for a caller that wants the rename without this backend.

**After the rename.** Every remaining name is compiled. A name with no table row is written as it appears (`CustomVendorField` stays `CustomVendorField`). Whether a deployment's parsers produce that field is a second decision, made by the caller. `compile_rules(..., gate=...)` can return a drop reason after the rename. `convert()` has no such gate: filter the collection first, or call `compile_rules` directly.

## Correlations

Standard correlation documents are parsed by pySigma. Two shapes are peeled out of the YAML first, because pySigma rejects their condition objects, and then compiled into the same `rules.corr.json`:

* `correlation.type: beaconing` with `cv_permille` and `n_buckets`
* `temporal` / `temporal_ordered` whose `condition` is a boolean string (SEP #198)

A correlation whose base rule did not compile is listed in `CompileResult.dropped` with a reason.

## Development

```
python3 -m pip install -e '.[dev]'
python3 -m pytest
```

Commits follow `docs/COMMIT.md`. Install the hook once:

```
git config core.hooksPath .githooks
git config commit.template .gitmessage
```
