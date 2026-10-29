# SPDX-License-Identifier: LGPL-2.1-only
"""Names under which pySigma discovers this package."""

import pytest

pytest.importorskip("sigma")

from sigma.backends.libsigma import LibsigmaBackend  # noqa: E402
from sigma.plugins import InstalledSigmaPlugins  # noqa: E402


def test_autodiscovered_names():
    plugins = InstalledSigmaPlugins.autodiscover()
    assert plugins.backends["libsigma"] is LibsigmaBackend
    assert "libsigma_ecs" in plugins.pipelines
    # pySigma keeps one flat pipeline namespace and lets a later plugin
    # overwrite an earlier one, so this package never claims a bare name.
    assert "ecs" not in plugins.pipelines
