# SPDX-License-Identifier: LGPL-2.1-only
"""Write a ``.sigmac`` artifact and, when correlations compiled, ``rules.corr.json``.

``sigma convert`` prints text. The ``.sigmac`` artifact is binary, so the
supported command for a file is this script.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

from .compiler import compile_directory, compile_rules
from .correlation import correlations_to_json


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
    args = parser.parse_args(argv)

    paths = [pathlib.Path(p) for p in args.paths]
    dirs = [p for p in paths if p.is_dir()]
    files = [p for p in paths if p.is_file()]
    unknown = [p for p in paths if not p.exists()]
    if unknown:
        print(f"not found: {unknown[0]}", file=sys.stderr)
        return 2

    ecs = not args.no_ecs
    if dirs and not files:
        result = compile_directory(
            dirs[0], *dirs[1:], ecs=ecs, keep_deprecated=args.keep_deprecated,
        )
    elif files and not dirs:
        chunks = [p.read_text(encoding="utf-8") for p in files]
        result = compile_rules(
            "\n---\n".join(chunks), ecs=ecs, keep_deprecated=args.keep_deprecated,
        )
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
