# SPDX-License-Identifier: LGPL-2.1-only
"""Write a ``.sigmac`` artifact and, when correlations compiled, ``rules.corr.json``.

``sigma convert`` prints text. The ``.sigmac`` artifact is binary, so the
supported command for a file is this script.

``--fields`` names the event fields a deployment produces. A rule that
reads any other field is dropped with a reason, and a correlation may group
only by a listed field. ``--placeholders`` supplies ``|expand`` values.
Both files are optional. Without them every parsed rule compiles.
"""

from __future__ import annotations

import argparse
import pathlib
import sys
from typing import Callable

from .compiler import compile_directory, compile_rules
from .correlation import correlations_to_json
from .pipeline import unmapped_drop_reason


class InputError(Exception):
    """A fields or placeholders file the compiler cannot use."""


def load_fields(path: pathlib.Path) -> Callable[[str], bool]:
    """Read one field name per line. ``#`` starts a comment.

    A line ``prefix.*`` accepts any field below ``prefix.``. Every other
    line is an exact name. The returned predicate is True for an accepted
    field.
    """
    exact: set[str] = set()
    prefixes: list[str] = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if any(ch.isspace() for ch in line):
            raise InputError(f"{path}:{number}: one field per line")
        if line.endswith(".*"):
            stem = line[:-1]
            if stem == ".":
                raise InputError(f"{path}:{number}: empty prefix")
            prefixes.append(stem)
        elif "*" in line:
            raise InputError(f"{path}:{number}: '*' is only allowed as a final '.*'")
        else:
            exact.add(line)
    if not exact and not prefixes:
        raise InputError(f"{path}: no field names")

    def accepted(name: str) -> bool:
        if name in exact:
            return True
        return any(name.startswith(p) and len(name) > len(p) for p in prefixes)

    return accepted


def load_placeholders(path: pathlib.Path) -> dict[str, list[str]]:
    """Read a YAML or JSON mapping of placeholder name to a string or a list."""
    import yaml

    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise InputError(f"{path}: {exc}") from exc
    if not isinstance(doc, dict) or not doc:
        raise InputError(f"{path}: expected a non-empty mapping")
    values: dict[str, list[str]] = {}
    for key, raw in doc.items():
        if not isinstance(key, str) or not key:
            raise InputError(f"{path}: placeholder names are strings")
        items = raw if isinstance(raw, list) else [raw]
        if not items or not all(isinstance(v, (str, int)) for v in items):
            raise InputError(f"{path}: {key!r} needs a string or a list of strings")
        values[key] = [str(v) for v in items]
    return values


def _detection_fields(detection) -> list[str]:
    fields: list[str] = []
    for item in getattr(detection, "detection_items", []):
        nested = getattr(item, "detection_items", None)
        if nested is not None:
            fields.extend(_detection_fields(item))
        elif getattr(item, "field", None):
            fields.append(item.field)
    return fields


def rule_fields(rule) -> list[str]:
    """Field names a rule reads, after the rename. Keyword items have none."""
    fields: list[str] = []
    for detection in rule.detection.detections.values():
        fields.extend(_detection_fields(detection))
    return fields


def field_gate(accepted: Callable[[str], bool]):
    """A ``compile_rules`` gate that drops rules reading an unlisted field."""

    def gate(rule, taxonomy):
        missing = sorted({f for f in rule_fields(rule) if not accepted(f)})
        if missing:
            return unmapped_drop_reason(missing, taxonomy)
        return None

    return gate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="libsigma-sigmac",
        description="Compile Sigma YAML to a libsigma .sigmac artifact.",
    )
    parser.add_argument("paths", nargs="+", help="rule files or directories")
    parser.add_argument("-o", "--output", required=True, help="output .sigmac path")
    parser.add_argument("--corr", help="write rules.corr.json to this path")
    parser.add_argument(
        "--no-ecs",
        action="store_true",
        help="do not rename Sigma field names to ECS",
    )
    parser.add_argument(
        "--keep-deprecated",
        action="store_true",
        help="compile rules marked deprecated or unsupported",
    )
    parser.add_argument(
        "--fields",
        help="file of produced field names; drop rules that read any other field",
    )
    parser.add_argument(
        "--placeholders",
        help="YAML or JSON mapping of |expand placeholder names to values",
    )
    args = parser.parse_args(argv)

    paths = [pathlib.Path(p) for p in args.paths]
    dirs = [p for p in paths if p.is_dir()]
    files = [p for p in paths if p.is_file()]
    unknown = [p for p in paths if not p.exists()]
    if unknown:
        print(f"not found: {unknown[0]}", file=sys.stderr)
        return 2

    gate = None
    field_ok = None
    placeholders = None
    try:
        if args.fields:
            field_ok = load_fields(pathlib.Path(args.fields))
            gate = field_gate(field_ok)
        if args.placeholders:
            placeholders = load_placeholders(pathlib.Path(args.placeholders))
    except (OSError, InputError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    options = dict(
        ecs=not args.no_ecs,
        keep_deprecated=args.keep_deprecated,
        placeholders=placeholders,
        gate=gate,
        field_ok=field_ok,
    )
    if dirs and not files:
        result = compile_directory(dirs[0], *dirs[1:], **options)
    elif files and not dirs:
        chunks = [p.read_text(encoding="utf-8") for p in files]
        result = compile_rules("\n---\n".join(chunks), **options)
    else:
        print("pass either files or directories, not both", file=sys.stderr)
        return 2

    out = pathlib.Path(args.output)
    out.write_bytes(result.artifact)
    if args.corr:
        pathlib.Path(args.corr).write_text(
            correlations_to_json(result.correlations), encoding="utf-8",
        )
    print(
        f"rules {len(result.sidecar)}  correlations {len(result.correlations)}  "
        f"dropped {len(result.dropped)}  errors {len(result.errors)}  "
        f"bytes {len(result.artifact)}",
        file=sys.stderr,
    )
    for err in result.errors:
        print(f"error: {err.get('title')}: {err.get('error')}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
