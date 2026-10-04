# SPDX-License-Identifier: LGPL-2.1-only
"""libsigma backend for pySigma.

Discovered as ``sigma.backends.libsigma`` with identifier ``libsigma``.
"""

from __future__ import annotations

from .yaml_compat import ensure_pysigma_yaml_loader

ensure_pysigma_yaml_loader()

from .backend import LibsigmaBackend  # noqa: E402

backends = {"libsigma": LibsigmaBackend}

__all__ = ["LibsigmaBackend", "backends"]
