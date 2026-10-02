# SPDX-License-Identifier: LGPL-2.1-only
"""Compiler and backend behavior that is part of the public contract."""

import struct

import pytest

pytest.importorskip("sigma")

from sigma.backends.libsigma import LibsigmaBackend  # noqa: E402
from sigma.backends.libsigma.compiler import compile_rules  # noqa: E402
from sigma.backends.libsigma.format import MAGIC  # noqa: E402
from sigma.collection import SigmaCollection  # noqa: E402


_PROCESS = """
title: Encoded PowerShell
id: aaaaaaaa-0000-0000-0000-000000000001
level: high
tags:
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  sel:
    Image|endswith: '\\powershell.exe'
  condition: sel
"""

_ECS_PROCESS = """
title: Encoded PowerShell
id: aaaaaaaa-0000-0000-0000-000000000001
taxonomy: ecs
level: high
logsource:
  category: process_creation
  product: windows
detection:
  sel:
    process.executable|endswith: '\\powershell.exe'
  condition: sel
"""

_ODD_FIELD = """
title: Odd field
id: aaaaaaaa-0000-0000-0000-000000000002
logsource:
  category: process_creation
  product: windows
detection:
  sel:
    CustomVendorField: 'x'
  condition: sel
"""


def _magic(blob: bytes) -> int:
    return struct.unpack_from("<I", blob, 0)[0]


def test_sigma_taxonomy_renames_image_to_ecs():
    res = compile_rules(_PROCESS)
    assert res.errors == []
    assert res.dropped == []
    assert b"process.executable" in res.artifact
    assert b"Image" not in res.artifact
    assert _magic(res.artifact) == MAGIC
    assert res.sidecar[1]["mitre"] == "T1059.001"
    assert res.sidecar[1]["verdict"] == "alert"


def test_ecs_taxonomy_keeps_names_as_written():
    res = compile_rules(_ECS_PROCESS)
    assert res.errors == []
    assert b"process.executable" in res.artifact
    assert b"Image" not in res.artifact


def test_ecs_false_keeps_the_sigma_name():
    res = compile_rules(_PROCESS, ecs=False)
    assert res.errors == []
    assert b"Image" in res.artifact
    assert b"process.executable" not in res.artifact


def test_unknown_field_is_compiled():
    """The backend does not know which fields a deployment produces."""
    res = compile_rules(_ODD_FIELD)
    assert res.errors == []
    assert res.dropped == []
    assert b"CustomVendorField" in res.artifact


def test_gate_can_drop_after_the_rename():
    def gate(rule, tax):
        fields = [
            it.field
            for det in rule.detection.detections.values()
            for it in det.detection_items
            if it.field
        ]
        if "process.executable" in fields and tax == "sigma":
            return "deployment does not produce process.executable"
        return None

    res = compile_rules(_PROCESS, gate=gate)
    assert res.sidecar == {}
    assert res.dropped[0]["reason"] == "deployment does not produce process.executable"


def test_backend_convert_returns_sigmac_bytes_and_corr_json():
    yaml = """
title: base
name: base_login
id: aaaaaaaa-0000-0000-0000-000000000010
logsource: {category: authentication, service: sshd}
detection:
  sel:
    User: root
  condition: sel
---
title: many failures
name: many_failures
status: stable
correlation:
  type: event_count
  rules:
    - base_login
  group-by:
    - User
  timespan: 10m
  condition:
    gte: 5
"""
    coll = SigmaCollection.from_yaml(yaml, resolve_references=False)
    backend = LibsigmaBackend()
    blob = backend.convert(coll, "sigmac")
    assert isinstance(blob, bytes)
    assert _magic(blob) == MAGIC
    text = backend.convert(coll, "corr")
    assert '"type": "event_count"' in text
    assert "user.name" in text
    assert backend.last_result.errors == []


def test_informational_is_benign_and_verdict_override_wins():
    res = compile_rules("""
title: context
level: informational
logsource: {category: firewall}
detection:
  sel:
    action: pass
  condition: sel
---
title: asked
level: informational
verdict: alert
logsource: {category: firewall}
detection:
  sel:
    action: block
  condition: sel
""")
    assert res.sidecar[1]["verdict"] == "benign"
    assert res.sidecar[2]["verdict"] == "alert"
    assert b"event.action" in res.artifact


def test_unresolved_placeholder_is_an_error():
    res = compile_rules("""
title: expand
logsource: {category: firewall}
detection:
  sel:
    src_ip|expand: '%edge%'
  condition: sel
""")
    assert res.sidecar == {}
    assert res.errors
    assert "edge" in res.errors[0]["error"]
