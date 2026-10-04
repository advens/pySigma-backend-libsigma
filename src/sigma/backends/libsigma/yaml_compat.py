# SPDX-License-Identifier: LGPL-2.1-only
"""Make pySigma importable when PyYAML has no libyaml C extension.

pySigma subclasses ``yaml.CSafeLoader``.  That attribute exists only when
PyYAML was built against libyaml.  FreeBSD (and any host whose internal
wheel is a pure-Python sdist build) often ships PyYAML without it, so
``python -m sigmac compile`` dies at import before a single rule is read.

CSafeLoader and SafeLoader implement the same safe YAML 1.1 subset (no
``!!python/object`` construction).  The C class is a libyaml speedup, not
a tighter sandbox.  Alias only the Safe* names so pysigma's
``class SigmaYAMLLoader(yaml.CSafeLoader)`` succeeds either way.  Do not
alias ``CLoader``/``CDumper`` onto ``Loader``/``Dumper``: those construct
arbitrary Python objects.

Call :func:`ensure_pysigma_yaml_loader` before any ``import sigma``.
"""

from __future__ import annotations


def ensure_pysigma_yaml_loader() -> None:
    import yaml

    if not hasattr(yaml, "CSafeLoader"):
        yaml.CSafeLoader = yaml.SafeLoader  # type: ignore[attr-defined, misc]
    if not hasattr(yaml, "CSafeDumper"):
        yaml.CSafeDumper = yaml.SafeDumper  # type: ignore[attr-defined, misc]
