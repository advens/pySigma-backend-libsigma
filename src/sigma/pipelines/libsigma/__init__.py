# SPDX-License-Identifier: LGPL-2.1-only
"""Optional Sigma-to-ECS rename for the libsigma backend.

The backend applies this pipeline itself when ``ecs=True`` and the rule
taxonomy is ``sigma``. Install it explicitly with ``sigma convert -p libsigma_ecs``
only when another backend should see the renamed fields.
"""

from __future__ import annotations

from sigma.backends.libsigma.pipeline import ecs_pipeline

pipelines = {"libsigma_ecs": ecs_pipeline}

__all__ = ["ecs_pipeline", "pipelines"]
